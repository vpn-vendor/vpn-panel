package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/ovpngen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	ovpnDir        = "/etc/openvpn/client"
	ovpnProfilePfx = "vpn-panel-"
	ovpnInstance   = "vpn-panel"
	ovpnUnit       = "openvpn-client@" + ovpnInstance + ".service"

	ovpnRunDir   = "/run/vpn-panel-ovpn"
	ovpnMgmtSock = ovpnRunDir + "/mgmt.sock"

	ovpnUpWait    = 6 * time.Second
	ovpnPushedTTL = 60 * time.Second
)

var (
	ovpnSystemctl  = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	ovpnJournalctl = []string{"/usr/bin/journalctl", "/bin/journalctl"}
)

type ovpnDriver struct {
	mu       sync.Mutex
	pushed   []string
	pushedAt time.Time

	peerIPv4 string
	sess     *mgmtSession
}

func newOvpnDriver() *ovpnDriver { return &ovpnDriver{} }

func (d *ovpnDriver) protocol() vpndriver.Protocol { return ovpngen.ID }
func (d *ovpnDriver) journal() []string            { return []string{"-u", ovpnUnit} }
func (d *ovpnDriver) iface() string                { return ovpngen.Descriptor.Iface }
func (d *ovpnDriver) passport(transport string) vpndriver.Passport {
	return ovpngen.Descriptor.Passport(transport)
}

func ovpnProfilePath(slug string) (string, error) {
	if !vpndriver.ValidSlug(slug) {
		return "", fmt.Errorf("недопустимое имя профиля")
	}
	return filepath.Join(ovpnDir, ovpnProfilePfx+slug+".conf"), nil
}

func ovpnLivePath() string { return filepath.Join(ovpnDir, ovpnInstance+".conf") }

func (d *ovpnDriver) importProfile(slug, text string) (vpndriver.Meta, []string, *agentrpc.ErrorObject) {
	path, err := ovpnProfilePath(slug)
	if err != nil {
		return vpndriver.Meta{}, nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "имя профиля составлено неверно — задайте название латиницей или кириллицей",
			Data:    map[string]any{"recoverable": false}}
	}
	profile, warnings, perr := ovpngen.Parse(text)
	if perr != nil {
		return vpndriver.Meta{}, nil, &agentrpc.ErrorObject{Code: codeVPNImport, Message: perr.Error(),
			Data: map[string]any{"recoverable": false}}
	}

	if err := durable.MkdirAll(ovpnDir, 0o700); err != nil {
		return vpndriver.Meta{}, nil, detailErr(errWriteConfig, err.Error(), true)
	}

	if err := durable.Write(path, profile.Library(), 0o600); err != nil {
		return vpndriver.Meta{}, nil, detailErr(errWriteConfig, err.Error(), true)
	}
	return profile.Meta(), warnings, nil
}

func (d *ovpnDriver) listProfiles() []string {
	entries, err := os.ReadDir(ovpnDir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ovpnProfilePfx) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(name, ovpnProfilePfx), ".conf"))
	}
	return out
}

func (d *ovpnDriver) profileText(slug string) (string, error) {
	path, err := ovpnProfilePath(slug)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) //nolint:gosec
	return string(data), err
}

func (d *ovpnDriver) removeProfile(slug string, active bool) error {
	path, err := ovpnProfilePath(slug)
	if err != nil {
		return err
	}
	if err := durable.Remove(path); err != nil {
		return err
	}
	if active {
		_ = durable.Remove(ovpnLivePath())
	}
	return nil
}

func (d *ovpnDriver) up(req upRequest) (upResult, *agentrpc.ErrorObject) {
	path, err := ovpnProfilePath(req.Slug)
	if err != nil {
		return upResult{}, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "имя профиля составлено неверно — обновите страницу",
			Data:    map[string]any{"recoverable": false}}
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return upResult{}, &agentrpc.ErrorObject{Code: codeVPNNotFound,
			Message: "файл подключения не найден на сервере — загрузите его заново",
			Data:    map[string]any{"recoverable": false}}
	}
	profile, _, perr := ovpngen.Parse(string(data))
	if perr != nil {
		return upResult{}, &agentrpc.ErrorObject{Code: codeVPNImport,
			Message: "сохранённый файл подключения повреждён — загрузите его заново",
			Data:    map[string]any{"recoverable": false, "detail": perr.Error()}}
	}

	remotes := make([]ovpngen.Remote, 0, len(profile.Remotes))
	for i, r := range profile.Remotes {
		addr, aerr := resolveEndpointAddr(r.Host, req.Mark)
		if aerr != nil {
			if i == 0 {
				return upResult{}, aerr
			}
			log.Printf("vpn: additional server %q skipped: %s", r.Host, aerr.Message)
			continue
		}
		remotes = append(remotes, ovpngen.Remote{Host: addr, Port: profile.PortOf(r), Proto: r.Proto})
	}
	res := upResult{EndpointIP: remotes[0].Host, EndpointPort: remotes[0].Port, Transport: profile.Transport(), Overhead: profile.Overhead(false)}

	mtu := req.MTU
	if mtu == 0 {
		mtu = autoTunnelMTU(res.EndpointIP, req.Mark, profile.Overhead(false))
	}
	live := profile.Generate(ovpngen.Render{
		Iface: d.iface(), Mark: req.Mark, MTU: mtu, Remotes: remotes, Management: ovpnMgmtSock,
	})
	if cur, err := os.ReadFile(ovpnLivePath()); err == nil && string(cur) == string(live) && d.unitRunning() { //nolint:gosec
		return res, nil
	}

	ensureNMDropIn()
	if aerr := d.checkForeignInterface(); aerr != nil {
		return upResult{}, aerr
	}
	if err := durable.MkdirAll(ovpnDir, 0o700); err != nil {
		return upResult{}, detailErr(errWriteConfig, err.Error(), true)
	}
	if err := durable.Write(ovpnLivePath(), live, 0o600); err != nil {
		return upResult{}, detailErr(errWriteConfig, err.Error(), true)
	}

	if aerr := d.systemctl("stop"); aerr != nil {
		return upResult{}, aerr
	}
	d.stopSession()

	if req.NewIntent {

		if aerr := d.systemctl("reset-failed"); aerr != nil {
			log.Printf("vpn: restart counter was not cleared (already clean?)")
		}
	}

	if aerr := d.systemctl("start", "--no-block"); aerr != nil {
		return upResult{}, aerr
	}
	d.ensureSession()
	deadline := time.Now().Add(ovpnUpWait)
	for time.Now().Before(deadline) && !d.present() {
		time.Sleep(300 * time.Millisecond)
	}

	if !d.present() && d.unitResult() == "start-limit-hit" {
		return upResult{}, errStartRefused()
	}
	res.Changed = true
	return res, nil
}

func (d *ovpnDriver) unitResult() string {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return ""
	}
	out, err := exec.Command(bin, "show", "-p", "Result", "--value", ovpnUnit).Output() //nolint:gosec
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (d *ovpnDriver) down() bool {
	if !d.unitActive() && !d.present() {
		return false
	}
	d.stopSession()
	if aerr := d.systemctl("stop"); aerr != nil {
		log.Printf("vpn: stop failed: %s", aerr.Message)
	}

	if d.present() {
		if ipBin, err := findBinary(ipCandidates); err == nil {
			_ = exec.Command(ipBin, "link", "del", d.iface()).Run() //nolint:gosec
		}
	}
	return true
}

func (d *ovpnDriver) present() bool { return ifacePresent(d.iface()) }

func (d *ovpnDriver) ensureRoutes() error {
	if !d.present() {
		return fmt.Errorf("интерфейс канала ещё не поднят")
	}
	return ensureTunnelRoutes(d.iface(), vpndriver.Mark)
}

func (d *ovpnDriver) facts() tunnelFacts {
	f := tunnelFacts{Present: d.present(), ProcRunning: d.unitRunning()}

	if d.unitLoaded() {
		d.ensureSession()
	}
	if snap, ok := d.snapshot(); ok {
		f.Connected = snap.Last.Connected && !snap.Exited
		f.TunnelIPv4 = snap.Last.LocalIPv4
		if snap.Last.Remote != "" && snap.Last.RemotePort > 0 {
			f.Endpoint = net.JoinHostPort(snap.Last.Remote, strconv.Itoa(snap.Last.RemotePort))
		}
		f.ProcState = snap.Last.Name
		f.FailReason = snap.Failure(time.Now().Unix())
		f.FailCount, f.LastFailUnix, f.ServerMessage = snap.FailCount, snap.LastFailUnix, snap.ServerMessage
	}
	if f.Present {
		f.RxBytes, f.TxBytes = ifaceCounters(d.iface())

		f.PayloadRx, f.PayloadTx = f.RxBytes, f.TxBytes
		f.KernelDataPlane = ifaceKind(d.iface()) == "ovpn"
		if f.TunnelIPv4 == "" {
			f.TunnelIPv4 = ifaceIPv4(d.iface())
		}

		f.ServicesMissing = f.Connected && !tunnelRoutesPresent(d.iface())
	}
	if f.Present && f.Connected {
		f.Pushed = d.pushedOptions()
		d.mu.Lock()
		f.PeerIPv4 = d.peerIPv4
		d.mu.Unlock()
	}
	return f
}

type mgmtSession struct {
	mu      sync.Mutex
	tracker ovpngen.Tracker
	seen    bool

	conn net.Conn
	stop chan struct{}
	done chan struct{}

	events chan struct{}
}

func (s *mgmtSession) wake() {
	select {
	case s.events <- struct{}{}:
	default:
	}
}

func (s *mgmtSession) send(cmd string) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("управляющий сокет канала не открыт")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return err
	}
	return nil
}

func (d *ovpnDriver) ensureSession() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != nil {
		return
	}
	s := &mgmtSession{stop: make(chan struct{}), done: make(chan struct{}),
		events: make(chan struct{}, 1)}
	d.sess = s
	go s.run()
}

func (d *ovpnDriver) stopSession() {
	d.mu.Lock()
	s := d.sess
	d.sess = nil
	d.mu.Unlock()
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done

	s.wake()
}

func (d *ovpnDriver) snapshot() (ovpngen.Tracker, bool) {
	d.mu.Lock()
	s := d.sess
	d.mu.Unlock()
	if s == nil {
		return ovpngen.Tracker{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tracker, s.seen
}

func (s *mgmtSession) run() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		if !s.serve() {

			select {
			case <-s.stop:
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
}

func (s *mgmtSession) serve() bool {
	conn, err := net.DialTimeout("unix", ovpnMgmtSock, 2*time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
	}()
	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		return false
	}

	s.mu.Lock()
	s.tracker.Reset()
	s.mu.Unlock()
	if _, err := conn.Write([]byte("state on all\nlog on\n")); err != nil {
		return false
	}
	read := false
	for {
		select {
		case <-s.stop:
			_, _ = conn.Write([]byte("quit\n"))
			return true
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := r.ReadString('\n')
		if line != "" {
			read = true
			s.mu.Lock()
			fails := s.tracker.FailCount
			if s.tracker.Feed(line) {
				s.seen = true
			}
			grew := s.tracker.FailCount > fails
			s.mu.Unlock()
			if grew {
				s.wake()
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return read
		}
	}
}

func (d *ovpnDriver) events() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return nil
	}
	return d.sess.events
}

func (d *ovpnDriver) pause(reason string) error {
	d.mu.Lock()
	s := d.sess
	d.mu.Unlock()
	if s == nil {
		return fmt.Errorf("канал не запущен — останавливать нечего")
	}
	if err := s.send("hold on"); err != nil {
		return err
	}
	if err := s.send("signal SIGUSR1"); err != nil {
		return err
	}
	log.Printf("vpn: connection attempts paused: %s", reason)
	return nil
}

func (d *ovpnDriver) resume() error {
	d.mu.Lock()
	s := d.sess
	d.mu.Unlock()
	if s == nil {
		return fmt.Errorf("канал не запущен")
	}
	if err := s.send("hold off"); err != nil {
		return err
	}
	if err := s.send("hold release"); err != nil {
		return err
	}
	log.Printf("vpn: connection attempts resumed")
	return nil
}

func (d *ovpnDriver) pushedOptions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.pushedAt) < ovpnPushedTTL {
		return d.pushed
	}
	d.pushedAt = time.Now()
	d.pushed, d.peerIPv4 = nil, ""
	bin, err := findBinary(ovpnJournalctl)
	if err != nil {
		return nil
	}
	out, err := exec.Command(bin, "-u", ovpnUnit, "-o", "cat", "-n", "400", "--no-pager").Output() //nolint:gosec
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if pushed := ovpngen.ParsePushReply(lines[i]); pushed != nil {
			d.pushed = ovpngen.RefusedPushes(pushed)

			d.peerIPv4 = ovpngen.PushedRouteGateway(pushed)
			break
		}
	}
	return d.pushed
}

func (d *ovpnDriver) unitActive() bool {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return false
	}
	return exec.Command(bin, "is-active", "--quiet", ovpnUnit).Run() == nil //nolint:gosec
}

func (d *ovpnDriver) unitState() string {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return ""
	}
	out, err := exec.Command(bin, "show", "-p", "ActiveState", "--value", ovpnUnit).Output() //nolint:gosec
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (d *ovpnDriver) unitLoaded() bool { return unitLoadedFrom(d.unitState()) }

func unitLoadedFrom(state string) bool { return state != "" && state != "inactive" }

func (d *ovpnDriver) unitRunning() bool { return unitRunningFrom(d.unitState()) }

func unitRunningFrom(state string) bool {
	switch state {
	case "active", "activating", "reloading", "deactivating":
		return true
	}
	return false
}

func (d *ovpnDriver) systemctl(action string, extra ...string) *agentrpc.ErrorObject {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return internalErr(errToolMissing, false)
	}
	args := append([]string{action}, extra...)
	args = append(args, ovpnUnit)
	if out, cerr := exec.Command(bin, args...).CombinedOutput(); cerr != nil { //nolint:gosec
		if action == "stop" {
			return &agentrpc.ErrorObject{Code: codeVPNUp,
				Message: "не удалось выключить защищённый канал — попробуйте ещё раз",
				Data:    map[string]any{"recoverable": true, "detail": firstLine(out)}}
		}
		if _, ferr := os.Stat("/usr/sbin/openvpn"); ferr != nil {
			return &agentrpc.ErrorObject{Code: codeVPNTool,
				Message: "средства защищённого канала этого типа не установлены на сервере — переустановите пакет или обратитесь в поддержку",
				Data:    map[string]any{"recoverable": false}}
		}
		return &agentrpc.ErrorObject{Code: codeVPNUp,
			Message: "не удалось включить защищённый канал. Проверьте, что сервер видит интернет, и попробуйте ещё раз",
			Data:    map[string]any{"recoverable": true, "detail": firstLine(out)}}
	}
	return nil
}

func (d *ovpnDriver) checkForeignInterface() *agentrpc.ErrorObject {
	kind := ifaceKind(d.iface())
	if kind == "" || kind == "ovpn" || kind == "tun" {
		return nil
	}
	return &agentrpc.ErrorObject{Code: codeVPNUp,
		Message: "имя служебного канала занято другим программным обеспечением — обратитесь в поддержку",
		Data:    map[string]any{"recoverable": false}}
}

var tunnelKinds = map[string]bool{
	"ovpn": true, "tun": true, "tap": true, "wireguard": true, "gre": true, "gretap": true,
	"ipip": true, "sit": true, "vti": true, "xfrm": true, "ip6tnl": true, "ifb": true,
}

func routeGetArgs(endpointIP string, mark int) []string {
	return []string{"-j", "route", "get", endpointIP, "mark", strconv.Itoa(mark)}
}

func tunnelMTUFromDev(dev string, kindOf func(string) string, mtuOf func(string) int, overhead int) (mtu int, note string) {
	devMTU := 1500
	switch {
	case dev == "":
		note = "маршрут до сервера не найден, взята карта по умолчанию"
	case tunnelKinds[kindOf(dev)]:
		note = "маршрут до сервера ведёт в туннель " + dev + ", взята карта по умолчанию"
	default:
		if m := mtuOf(dev); m > 0 {
			devMTU = m
		}
	}
	return vpndriver.TunnelMTU(devMTU, overhead), note
}

func autoTunnelMTU(endpointIP string, mark, overhead int) int {
	dev := ""
	if ipBin, err := findBinary(ipCandidates); err == nil {
		if out, err := exec.Command(ipBin, routeGetArgs(endpointIP, mark)...).Output(); err == nil { //nolint:gosec
			var routes []struct {
				Dev string `json:"dev"`
			}
			if json.Unmarshal(out, &routes) == nil && len(routes) > 0 {
				dev = routes[0].Dev
			}
		}
	}
	mtu, note := tunnelMTUFromDev(dev, ifaceKind, readIfaceMTU, overhead)
	if note != "" {
		log.Printf("vpn: packet size: %s (tun-mtu %d)", note, mtu)
	}
	return mtu
}
