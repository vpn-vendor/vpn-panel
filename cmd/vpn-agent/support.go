package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/supportfmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/supportmask"
)

const (
	supportKeyFile = "/etc/vpn-panel/support.key"

	supportDir = "/run/vpn-panel"

	supportPrefix = "vpn-panel-support-"
)

const (
	codeSupportBusy = 2201
	codeSupportFail = 2202
)

const supportJournalFor = 7 * 24 * time.Hour

const supportCmdTimeout = 60 * time.Second

const supportGzipOver = 1 << 20

const supportSpaceShare = 4

type supportInput struct {
	Names []struct {
		Name string `json:"name"`
		MAC  string `json:"mac"`
	} `json:"names"`

	Parts map[string][]string `json:"parts"`
}

type supportRun struct {
	w     *supportfmt.Writer
	m     *supportmask.Masker
	exec  func(argv ...string) ([]byte, error)
	since time.Time
	a     *supportApplier

	room int
}

func (c *supportRun) line(s string) { c.w.Line(c.m.Line(s)) }

func (c *supportRun) text(out []byte) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		c.line(sc.Text())
	}
}

func (c *supportRun) cmd(title string, argv ...string) {
	c.w.Line("# " + title)
	out, err := c.exec(argv...)
	c.text(out)
	if err != nil {
		c.w.Line("# команда не выполнилась")
	}
}

func (c *supportRun) journal(args ...string) {
	argv := append([]string{"journalctl", "--no-pager", "-o", "short-iso", "-n", strconv.Itoa(c.room),
		"--since", c.since.UTC().Format("2006-01-02 15:04:05 UTC")}, args...)
	out, err := c.exec(argv...)
	if bytes.Count(out, []byte{'\n'}) >= c.room {
		c.w.Line("# журнал длиннее предела раздела: показаны последние " + strconv.Itoa(c.room) + " строк")
	}
	c.text(out)
	if err != nil {
		c.w.Line("# журнал не прочитан")
	}
}

func (c *supportRun) json(title string, v any, aerr *agentrpc.ErrorObject) {
	c.w.Line("# " + title)
	if aerr != nil {
		c.w.Line("# состояние не получено")
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		c.w.Line("# состояние не записано")
		return
	}
	c.text(data)
}

var supportCollectors = map[string]func(c *supportRun){
	"versions": func(c *supportRun) {
		c.w.Line("системная служба: " + agentVersion)
		c.cmd("пакет панели", "dpkg-query", "-W", "-f", "${Package} ${Version} ${Status}\n", "vpn-panel")
		c.cmd("система", "sh", "-c", ". /etc/os-release; echo \"$PRETTY_NAME\"")
		c.cmd("ядро", "uname", "-srm")
		c.cmd("время работы и нагрузка", "uptime")
		c.cmd("часы", "timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone", "-p", "TimeUSec")
	},
	"hardware": func(c *supportRun) {
		c.cmd("процессор", "sh", "-c", "grep -m1 'model name' /proc/cpuinfo; nproc")
		c.cmd("память", "sh", "-c", "grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo")
		c.cmd("диски", "lsblk", "-dno", "NAME,SIZE,ROTA,TYPE,TRAN")
		c.cmd("место", "df", "-h", "/", "/var", "/boot", "/run")
		c.cmd("сетевые карты", "sh", "-c", "for d in /sys/class/net/*; do n=${d##*/}; [ -e $d/device ] || continue; echo \"$n $(basename $(readlink -f $d/device/driver 2>/dev/null) 2>/dev/null) $(cat $d/speed 2>/dev/null) $(cat $d/duplex 2>/dev/null) $(cat $d/operstate 2>/dev/null)\"; done")
	},
	"links": func(c *supportRun) {
		c.cmd("адреса", "ip", "-br", "addr")
		c.cmd("счётчики карт", "ip", "-s", "-s", "link")
		c.cmd("маршруты", "ip", "route", "show", "table", "all")
		c.cmd("правила маршрутизации", "ip", "rule")
		c.cmd("очереди", "tc", "-s", "qdisc", "show")
	},
	"neighbours": func(c *supportRun) {
		c.cmd("соседи", "ip", "neigh", "show")
		c.cmd("мосты", "bridge", "link", "show")
	},
	"status": func(c *supportRun) {
		if c.a == nil {
			return
		}
		v, aerr := networkStatus(nil)
		c.json("сеть", v, aerr)
		v, aerr = c.a.firewall.firewallStatus(nil)
		c.json("защита", v, aerr)
		v, aerr = c.a.qos.qosStatus(nil)
		c.json("QoS", v, aerr)
		v, aerr = c.a.vpn.vpnStatus(nil)
		c.json("канал", v, aerr)
		v, aerr = c.a.updates.updatesStatus(nil)
		c.json("обновления", v, aerr)
		v, aerr = c.a.disk.diskStatus(nil)
		c.json("диск", v, aerr)
	},
	"firewall": func(c *supportRun) {
		c.cmd("правила", "nft", "list", "table", "inet", "vpn_panel")
	},
	"services": func(c *supportRun) {
		c.cmd("службы", "systemctl", "--no-pager", "--plain", "list-units", "--type=service", "--all")
		c.cmd("отказавшие службы", "systemctl", "--no-pager", "--plain", "--failed")
	},
	"journal-agent": func(c *supportRun) { c.journal("-u", "vpn-agent.service") },
	"journal-panel": func(c *supportRun) { c.journal("-u", "vpn-panel.service", "-u", "vpn-panel-firewall.service") },
	"journal-channel": func(c *supportRun) {
		if c.a == nil {
			return
		}

		for _, d := range c.a.vpn.drivers {
			if args := d.journal(); len(args) > 0 {
				c.journal(args...)
			}
		}
	},
	"journal-network": func(c *supportRun) { c.journal("-u", "systemd-networkd.service", "-u", "NetworkManager.service") },

	"journal-provider": func(c *supportRun) { c.journal("-t", "pppd", "-t", "pppoe") },
	"journal-dhcp":     func(c *supportRun) { c.journal("-u", "kea-dhcp4-server.service") },
	"journal-dns":      func(c *supportRun) { c.journal("-u", "unbound.service", "-u", "systemd-resolved.service") },
	"journal-kernel":   func(c *supportRun) { c.journal("-k") },
}

func writeSupport(out io.Writer, in supportInput, m *supportmask.Masker, now time.Time, a *supportApplier,
	run func(argv ...string) ([]byte, error)) error {
	for _, n := range in.Names {
		m.Known(n.Name, n.MAC)
	}
	w := supportfmt.NewWriter(out, supportfmt.Known(), [][2]string{
		{"собрано", now.UTC().Format(time.RFC3339)},
		{"журнал с", now.Add(-supportJournalFor).UTC().Format(time.RFC3339)},
		{"разделы панели", map[bool]string{true: "есть", false: "нет: файл собран без панели"}[len(in.Parts) > 0]},
	})
	c := &supportRun{w: w, m: m, exec: run, since: now.Add(-supportJournalFor), a: a}
	for _, p := range supportfmt.Parts {
		if p.Source == supportfmt.FromPanel {
			lines, ok := in.Parts[p.ID]
			if !ok {
				continue
			}
			if err := w.Begin(p.ID); err != nil {
				return err
			}
			for _, l := range lines {
				c.line(l)
			}
			continue
		}
		collect, ok := supportCollectors[p.ID]
		if !ok {
			return fmt.Errorf("support: у раздела %q нет сборщика", p.ID)
		}
		if err := w.Begin(p.ID); err != nil {
			return err
		}

		c.room = p.MaxLines - 4
		collect(c)
	}
	return w.Close()
}

func supportExec(argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), supportCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	return cmd.Output()
}

type supportState struct {
	State string `json:"state"`
	Path  string `json:"path,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
	Lines int    `json:"lines,omitempty"`
	At    int64  `json:"at,omitempty"`
}

type supportApplier struct {
	mu       sync.Mutex
	st       supportState
	limiter  *ratelimit.Limiter
	firewall *firewallApplier
	qos      *qosApplier
	vpn      *vpnApplier
	updates  *updatesApplier
	disk     *diskApplier

	leases func() []Lease
}

func newSupportApplier(f *firewallApplier, q *qosApplier, v *vpnApplier, u *updatesApplier, d *diskApplier) *supportApplier {
	return &supportApplier{st: supportState{State: "idle"}, limiter: ratelimit.New(3, 1, 10*time.Minute),
		firewall: f, qos: q, vpn: v, updates: u, disk: d}
}

func supportKey() ([]byte, error) {
	if key, err := os.ReadFile(supportKeyFile); err == nil && len(key) >= 32 {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := durable.MkdirAll(filepath.Dir(supportKeyFile), 0o750); err != nil {
		return nil, err
	}

	if err := durable.Write(supportKeyFile, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *supportApplier) supportCollect(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var in supportInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, invalidParams()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.State == "running" {
		return nil, agentrpc.Busy(codeSupportBusy, "сведения уже собираются — подождите", time.Minute)
	}
	if !s.limiter.Allow("collect") {
		return nil, agentrpc.Busy(codeSupportBusy, "сведения запрашиваются слишком часто — подождите", s.limiter.RetryIn("collect"))
	}
	s.st = supportState{State: "running", At: time.Now().Unix()}
	go s.run(in)
	return s.st, nil
}

const supportNamesMax = 4096

func (s *supportApplier) supportNames(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		MACs []string `json:"macs"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || len(p.MACs) > supportNamesMax {
		return nil, invalidParams()
	}
	key, err := supportKey()
	if err != nil {
		return nil, detailErr("не удалось получить условные имена — повторите; если повторяется, обратитесь в поддержку", err.Error(), true)
	}
	m := supportmask.New(key)
	out := make(map[string]string, len(p.MACs))
	for _, mac := range p.MACs {
		out[mac] = m.Device(mac)
	}
	return map[string]any{"names": out}, nil
}

func (s *supportApplier) supportStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

func (s *supportApplier) run(in supportInput) {
	st, err := s.build(in)
	if err != nil {
		log.Printf("support: not collected: %v", err)
		st = supportState{State: "failed", At: time.Now().Unix()}
	}
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

func (s *supportApplier) build(in supportInput) (supportState, error) {
	key, err := supportKey()
	if err != nil {
		return supportState{}, err
	}
	m := supportmask.New(key)
	for _, slug := range s.vpn.listProfiles() {
		m.Alias(slug, m.Profile(slug))
	}
	if s.leases != nil {
		for _, l := range s.leases() {
			m.Known(l.Hostname, l.MAC)
		}
	}
	now := time.Now()
	limit := supportRoom()

	var text bytes.Buffer
	if err := writeSupport(&capWriter{w: &text, left: limit}, in, m, now, s, supportExec); err != nil {
		return supportState{}, err
	}

	rep, err := supportfmt.Check(bytes.NewReader(text.Bytes()), io.Discard, supportfmt.Known(), limit)
	if err != nil {
		return supportState{}, fmt.Errorf("собранный файл не проходит собственную проверку: %w", err)
	}
	name := supportPrefix + now.UTC().Format("20060102-150405") + ".txt"
	data := text.Bytes()
	if len(data) > supportGzipOver {
		var packed bytes.Buffer
		zw := gzip.NewWriter(&packed)
		if _, err := zw.Write(data); err != nil {
			return supportState{}, err
		}
		if err := zw.Close(); err != nil {
			return supportState{}, err
		}
		name, data = name+".gz", packed.Bytes()
	}
	old, _ := filepath.Glob(filepath.Join(supportDir, supportPrefix+"*"))
	for _, p := range old {
		_ = durable.Remove(p)
	}
	path := filepath.Join(supportDir, name)

	if err := durable.Write(path, data, 0o640, durable.Owner(0, dirGroup(supportDir))); err != nil {
		return supportState{}, err
	}
	log.Printf("support: collected, %d lines", rep.Lines)
	return supportState{State: "done", Path: path, Bytes: int64(len(data)), Lines: rep.Lines, At: now.Unix()}, nil
}

func supportRoom() int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(supportDir, &st); err != nil {
		return supportGzipOver
	}
	return int64(st.Bavail) * st.Bsize / supportSpaceShare //nolint:gosec
}

func dirGroup(dir string) int {
	info, err := os.Stat(dir)
	if err != nil {
		return 0
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	return 0
}

type capWriter struct {
	w    io.Writer
	left int64
}

var errSupportTooBig = errors.New("файл сведений больше отведённого места")

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		return 0, errSupportTooBig
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

func runSupport() int {
	socketPath, err := sanitizeSocketPath(os.Getenv("AGENT_SOCKET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Служба панели настроена неверно — обратитесь в поддержку.")
		return 1
	}
	client := &agentrpc.Client{SocketPath: socketPath}
	resp, err := client.Call("support.collect", map[string]any{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Служба панели не отвечает — перезагрузите шлюз и повторите.")
		return 1
	}
	if resp.Error != nil {
		fmt.Fprintln(os.Stderr, "Сведения не собраны: "+resp.Error.Message+".")
		return 1
	}
	fmt.Fprintln(os.Stderr, "Собираю сведения для поддержки, это займёт до нескольких минут…")
	var st supportState
	for deadline := time.Now().Add(15 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		resp, err := client.Call("support.status", map[string]any{})
		if err != nil || resp.Error != nil || json.Unmarshal(resp.Result, &st) != nil {
			continue
		}
		if st.State != "running" {
			break
		}
	}
	if st.State != "done" {
		fmt.Fprintln(os.Stderr, "Сведения не собраны — повторите; если повторяется, обратитесь в поддержку.")
		return 1
	}

	fmt.Println(st.Path)
	return 0
}
