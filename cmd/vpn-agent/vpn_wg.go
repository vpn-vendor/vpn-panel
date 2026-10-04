package main

import (
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

const (
	wgDir        = "/etc/wireguard"
	wgProfilePfx = "vpn-panel-"
)

var (
	wgQuickCandidates = []string{"/usr/bin/wg-quick", "/usr/sbin/wg-quick", "/bin/wg-quick"}
	wgCandidates      = []string{"/usr/bin/wg", "/usr/sbin/wg", "/bin/wg"}
)

var wgEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

type wgDriver struct{}

func (d *wgDriver) protocol() vpndriver.Protocol { return wggen.ID }
func (d *wgDriver) journal() []string            { return nil }
func (d *wgDriver) iface() string                { return wggen.Descriptor.Iface }
func (d *wgDriver) passport(string) vpndriver.Passport {
	return wggen.Descriptor.Passport("")
}

func profilePath(slug string) (string, error) {
	if !vpndriver.ValidSlug(slug) {
		return "", fmt.Errorf("недопустимое имя профиля")
	}
	return filepath.Join(wgDir, wgProfilePfx+slug+".conf"), nil
}

func livePath() string { return filepath.Join(wgDir, wggen.Iface+".conf") }

func wgLiveMark() (int, bool) {
	bin, err := findBinary(wgCandidates)
	if err != nil {
		return 0, false
	}
	out, err := exec.Command(bin, "show", wggen.Iface, "fwmark").Output() //nolint:gosec
	if err != nil {
		return 0, false
	}
	mark := wggen.ParseFwmark(out)
	return mark, mark > 0
}

func (d *wgDriver) importProfile(slug, text string) (vpndriver.Meta, []string, *agentrpc.ErrorObject) {
	path, err := profilePath(slug)
	if err != nil {
		return vpndriver.Meta{}, nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "имя профиля составлено неверно — задайте название латиницей или кириллицей",
			Data:    map[string]any{"recoverable": false}}
	}
	profile, warnings, perr := wggen.Parse(text)
	if perr != nil {
		return vpndriver.Meta{}, nil, &agentrpc.ErrorObject{Code: codeVPNImport, Message: perr.Error(),
			Data: map[string]any{"recoverable": false}}
	}
	if err := durable.MkdirAll(wgDir, 0o700); err != nil {
		return vpndriver.Meta{}, nil, detailErr(errWriteConfig, err.Error(), true)
	}

	if err := durable.Write(path, profile.Generate(wggen.Render{}), 0o600); err != nil {
		return vpndriver.Meta{}, nil, detailErr(errWriteConfig, err.Error(), true)
	}
	return profile.Meta(), warnings, nil
}

func (d *wgDriver) listProfiles() []string {
	entries, err := os.ReadDir(wgDir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, wgProfilePfx) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(name, wgProfilePfx), ".conf"))
	}
	return out
}

func (d *wgDriver) profileText(slug string) (string, error) {
	path, err := profilePath(slug)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) //nolint:gosec
	return string(data), err
}

func (d *wgDriver) removeProfile(slug string, active bool) error {
	path, err := profilePath(slug)
	if err != nil {
		return err
	}
	if err := durable.Remove(path); err != nil {
		return err
	}
	if active {
		_ = durable.Remove(livePath())
	}
	return nil
}

func (d *wgDriver) up(req upRequest) (upResult, *agentrpc.ErrorObject) {
	path, err := profilePath(req.Slug)
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
	profile, _, perr := wggen.Parse(string(data))
	if perr != nil {
		return upResult{}, &agentrpc.ErrorObject{Code: codeVPNImport,
			Message: "сохранённый файл подключения повреждён — загрузите его заново",
			Data:    map[string]any{"recoverable": false, "detail": perr.Error()}}
	}

	endpointIP, aerr := resolveEndpointAddr(profile.Peer.EndpointHost, req.Mark)
	if aerr != nil {
		return upResult{}, aerr
	}
	res := upResult{EndpointIP: endpointIP, EndpointPort: profile.Peer.EndpointPort, Transport: vpndriver.TransportUDP}

	live := profile.Generate(wggen.Render{MTU: req.MTU, EndpointAddr: endpointIP, Mark: vpndriver.Mark})
	if cur, err := os.ReadFile(livePath()); err == nil && string(cur) == string(live) && d.present() { //nolint:gosec
		return res, nil
	}

	ensureNMDropIn()
	if aerr := d.checkForeignInterface(); aerr != nil {
		return upResult{}, aerr
	}
	if err := durable.Write(livePath(), live, 0o600); err != nil {
		return upResult{}, detailErr(errWriteConfig, err.Error(), true)
	}
	if aerr := d.wgQuick("down"); aerr != nil && d.present() {
		return upResult{}, aerr
	}
	if aerr := d.wgQuick("up"); aerr != nil {
		return upResult{}, aerr
	}
	res.Changed = true
	return res, nil
}

func (d *wgDriver) down() bool {
	if !d.present() {
		return false
	}
	if aerr := d.wgQuick("down"); aerr != nil {
		log.Printf("vpn: bring down failed: %s", aerr.Message)
		return false
	}
	return true
}

func (d *wgDriver) present() bool { return ifacePresent(d.iface()) }

func (d *wgDriver) ensureRoutes() error {
	if !d.present() {
		return fmt.Errorf("интерфейс канала ещё не поднят")
	}
	return ensureTunnelRoutes(d.iface(), vpndriver.Mark)
}

func (d *wgDriver) facts() tunnelFacts {
	f := tunnelFacts{Present: d.present(), KernelDataPlane: true}
	if !f.Present {
		return f
	}
	f.TunnelIPv4 = ifaceIPv4(d.iface())

	rxb, txb := ifaceCounters(d.iface())
	rxp, txp := ifacePackets(d.iface())
	f.PayloadRx, f.PayloadTx = wgPayload(rxb, rxp), wgPayload(txb, txp)
	bin, err := findBinary(wgCandidates)
	if err != nil {
		return f
	}
	hs, _ := exec.Command(bin, "show", d.iface(), "latest-handshakes").Output() //nolint:gosec
	tr, _ := exec.Command(bin, "show", d.iface(), "transfer").Output()          //nolint:gosec
	ep, _ := exec.Command(bin, "show", d.iface(), "endpoints").Output()         //nolint:gosec
	peers := wggen.PeerStates(hs, tr, ep)
	if len(peers) == 0 {
		return f
	}
	p := peers[0]
	f.RxBytes, f.TxBytes, f.Endpoint = p.RxBytes, p.TxBytes, p.Endpoint
	if p.HandshakeUnix > 0 {
		f.Connected = true
		f.AgeSec = time.Now().Unix() - p.HandshakeUnix
	}
	return f
}

const wgDataOverhead = 32

func wgPayload(bytes, packets int64) int64 { return max(0, bytes-wgDataOverhead*packets) }

func (d *wgDriver) wgQuick(action string) *agentrpc.ErrorObject {
	bin, err := findBinary(wgQuickCandidates)
	if err != nil {
		return &agentrpc.ErrorObject{Code: codeVPNTool,
			Message: "средства защищённого канала не установлены на сервере — переустановите пакет или обратитесь в поддержку",
			Data:    map[string]any{"recoverable": false}}
	}
	cmd := exec.Command(bin, action, d.iface()) //nolint:gosec
	cmd.Env = wgEnv
	if out, cerr := cmd.CombinedOutput(); cerr != nil {
		if action == "down" {
			return &agentrpc.ErrorObject{Code: codeVPNUp,
				Message: "не удалось выключить защищённый канал — попробуйте ещё раз",
				Data:    map[string]any{"recoverable": true, "detail": firstLine(out)}}
		}
		return &agentrpc.ErrorObject{Code: codeVPNUp,
			Message: "не удалось включить защищённый канал. Проверьте, что сервер видит интернет, и попробуйте ещё раз",
			Data:    map[string]any{"recoverable": true, "detail": firstLine(out)}}
	}
	return nil
}

func (d *wgDriver) checkForeignInterface() *agentrpc.ErrorObject {
	kind := ifaceKind(d.iface())
	if kind == "" || kind == "wireguard" {
		return nil
	}
	return &agentrpc.ErrorObject{Code: codeVPNUp,
		Message: "имя служебного канала занято другим программным обеспечением — обратитесь в поддержку",
		Data:    map[string]any{"recoverable": false}}
}
