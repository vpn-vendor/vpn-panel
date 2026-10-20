package legacyvpn

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type UnitState func(unit string) (enabled, active bool)

type Danger struct {
	ID         string
	Attributed bool
	Support    []string
}

type Report struct {
	Markers []string
	Gateway bool
	Mode    string
	Danger  []Danger
	PPPoE   bool
	Tunnel  bool
	Rerun   []string
	Support []string
}

const (
	modeVPN          = "vpn"
	modeDirect       = "direct"
	modeRemnants     = "remnants"
	modeUnrecognized = "unrecognized"

	dangerSudo     = "sudo"
	dangerRoot     = "root_service"
	dangerTerminal = "terminal"
	dangerUSB      = "usb"

	rerunNetplanMoved = "panel_netplan_moved"
)

const (
	netplanDir     = "/etc/netplan"
	scriptNetplan  = "/etc/netplan/99-vpn-script.yaml"
	panelNetplan   = "99-vpn-panel.yaml"
	resolvedConf   = "/etc/systemd/resolved.conf"
	resolvedHeader = "# Файл автоматически сгенерирован скриптом vpn.sh"
	udevDir        = "/etc/udev/rules.d"
	udevRule       = "/etc/udev/rules.d/99-usb-automount.rules"
	mountUSB       = "/usr/local/bin/mount-usb.sh"
	mountUSBName   = "mount-usb.sh"
	unitDir        = "/etc/systemd/system"
	botUnit        = "/etc/systemd/system/telegram_bot.service"
	terminalUnit   = "shellinabox.service"
	openvpnConf    = "/etc/openvpn/client1.conf"
	wireguardConf  = "/etc/wireguard/tun0.conf"
	rulesV4        = "/etc/iptables/rules.v4"
	tunnelIface    = "tun0"
	sudoersFile    = "/etc/sudoers"
	crontabFile    = "/etc/crontab"
)

var backupName = regexp.MustCompile(`^backup_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$`)

var ownUnits = []struct{ name, prog string }{
	{"home_metrics_daemon", "home_metrics_daemon.py"},
	{"network_load", "update_network_load.py"},
	{"ping_daemon", "ping_daemon.sh"},
	{"telegram_bot", "bot_source/bot.py"},
	{"update_metrics", "update_metrics_daemon.py"},
	{"vpn_mtu_daemon", "vpn_mtu_daemon.sh"},
}

var ownScripts = []struct{ id, path string }{
	{"script_mount_usb", mountUSB},
	{"script_ping_daemon", "/usr/local/bin/ping_daemon.sh"},
	{"script_vpn_mtu_daemon", "/usr/local/bin/vpn_mtu_daemon.sh"},
}

var gatewayUnits = []string{
	"apache2.service",
	"isc-dhcp-server.service",
	"openvpn@client1.service",
	"ping_daemon.service",
	"shellinabox.service",
	"telegram_bot.service",
	"vpn_mtu_daemon.service",
	"wg-quick@tun0.service",
}

var tunnelUnits = []string{"openvpn@client1.service", "wg-quick@tun0.service"}

var markerStep = map[string]string{
	"netplan_file": "netplan", "netplan_backup": "netplan",
	"udev_rule": "usb", "script_mount_usb": "usb",
	"unit_ping_daemon": "ping", "script_ping_daemon": "ping",
	"unit_vpn_mtu_daemon": "mtu", "script_vpn_mtu_daemon": "mtu",
}

func steps(markers []string) int {
	seen := map[string]bool{}
	for _, m := range markers {
		step := markerStep[m]
		if step == "" {
			step = m
		}
		seen[step] = true
	}
	return len(seen)
}

func (r Report) Without(markers []string) Report {
	if len(markers) == 0 {
		return r
	}
	out := r
	out.Markers = slices.DeleteFunc(slices.Clone(r.Markers), func(m string) bool { return slices.Contains(markers, m) })
	out.Gateway = steps(out.Markers) >= 2
	if !out.Gateway {
		out.Mode = ""
		out.Danger = slices.Clone(r.Danger)
		for i := range out.Danger {
			out.Danger[i].Attributed = false
		}
	}
	return out
}

func Gateway(root string) bool {
	var sup pathSet
	return steps(host{root: root}.markers(&sup)) >= 2
}

func ModeWord(mode string) string {
	return map[string]string{modeVPN: "режим VPN", modeDirect: "прямой режим",
		modeRemnants: "остатки после удаления", modeUnrecognized: "версия не опознана"}[mode]
}

func Units() []string {
	out := append([]string(nil), gatewayUnits...)
	for _, u := range append(tunnelUnits, terminalUnit) {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

func Detect(root string, units UnitState) Report {
	h := host{root: root}
	var sup pathSet
	var r Report

	r.Markers = h.markers(&sup)
	r.Gateway = steps(r.Markers) >= 2
	if r.Gateway {
		r.Mode = h.mode(units, &sup)
	}
	r.Danger = h.dangers(units, r.Gateway)
	if h.pppoe() {
		r.PPPoE = true
		sup.add(crontabFile)
	}
	if units != nil {
		for _, u := range tunnelUnits {
			if _, active := units(u); active {
				r.Tunnel = true
				sup.add(u)
			}
		}
	}
	if moved := h.panelNetplanMoved(); len(moved) > 0 {
		r.Rerun = []string{rerunNetplanMoved}
		sup.add(moved...)
	}
	r.Support = sup.list()
	return r
}

func (h host) markers(sup *pathSet) []string {
	var ids []string
	found := func(id string, paths ...string) {
		ids = append(ids, id)
		sup.add(paths...)
	}
	if h.isFile(scriptNetplan) {
		found("netplan_file", scriptNetplan)
	}
	var backups []string
	for _, e := range h.readDir(netplanDir) {
		if e.IsDir() && backupName.MatchString(e.Name()) {
			backups = append(backups, netplanDir+"/"+e.Name())
		}
	}
	if len(backups) > 0 {
		found("netplan_backup", backups...)
	}
	for _, u := range ownUnits {
		p := unitDir + "/" + u.name + ".service"
		if data, ok := h.read(p); ok && execStartRuns(data, u.prog) {
			found("unit_"+u.name, p)
		}
	}
	for _, s := range ownScripts {
		if h.isFile(s.path) {
			found(s.id, s.path)
		}
	}
	if data, ok := h.read(udevRule); ok && mentions(data, mountUSBName) {
		found("udev_rule", udevRule)
	}
	if data, ok := h.read(resolvedConf); ok && hasLine(data, resolvedHeader) {
		found("resolved_header", resolvedConf)
	}
	slices.Sort(ids)
	return ids
}

func (h host) mode(units UnitState, sup *pathSet) string {
	if units != nil && !anyUnit(units, gatewayUnits) {
		return modeRemnants
	}
	vpn := false
	for _, p := range []string{openvpnConf, wireguardConf} {
		if h.isFile(p) {
			vpn = true
			sup.add(p)
		}
	}
	rules, haveRules := h.read(rulesV4)
	if haveRules {
		sup.add(rulesV4)
		vpn = vpn || hasField(rules, tunnelIface)
	}
	switch {
	case vpn:
		return modeVPN
	case haveRules:
		return modeDirect
	}
	return modeUnrecognized
}

func (h host) dangers(units UnitState, gateway bool) []Danger {
	var ds []Danger
	add := func(id string, support []string) {
		if len(support) > 0 {
			ds = append(ds, Danger{ID: id, Attributed: gateway, Support: support})
		}
	}
	add(dangerSudo, h.sudoHits())
	add(dangerRoot, h.rootService())
	if units != nil && anyUnit(units, []string{terminalUnit}) {
		add(dangerTerminal, []string{terminalUnit})
	}
	add(dangerUSB, h.usbHits())
	return ds
}

func (h host) sudoHits() []string {
	seen := map[string]bool{}
	var hits []string
	var visit func(p string)
	visit = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		data, ok := h.read(p)
		if !ok {
			return
		}
		hit := false
		for _, line := range joinContinued(data) {
			t := strings.TrimSpace(line)
			f := strings.Fields(t)
			if len(f) == 0 {
				continue
			}
			switch f[0] {
			case "#includedir", "@includedir":
				if len(f) > 1 {
					for _, n := range h.sudoersDir(sudoersPath(p, f[1])) {
						visit(n)
					}
				}
				continue
			case "#include", "@include":
				if len(f) > 1 {
					visit(sudoersPath(p, f[1]))
				}
				continue
			}

			if isWebUser(f[0]) && grantsRoot(t) {
				hit = true
			}
		}
		if hit {
			hits = append(hits, p)
		}
	}
	visit(sudoersFile)
	slices.Sort(hits)
	return hits
}

func (h host) sudoersDir(dir string) []string {
	var out []string
	for _, e := range h.readDir(dir) {
		n := e.Name()
		if strings.HasSuffix(n, "~") || strings.Contains(n, ".") {
			continue
		}
		if p := dir + "/" + n; h.isFile(p) {
			out = append(out, p)
		}
	}
	return out
}

func sudoersPath(from, arg string) string {
	arg = strings.Trim(arg, `"`)
	if filepath.IsAbs(arg) {
		return filepath.Clean(arg)
	}
	return filepath.Join(filepath.Dir(from), arg)
}

var rootCommands = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true,
	"su": true, "sudo": true, "sudoedit": true}

var sudoTag = regexp.MustCompile(`^[A-Z_]+:\s*`)

func grantsRoot(line string) bool {
	_, rest, ok := strings.Cut(line, "=")
	if !ok {
		return false
	}
	rest = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(rest, "")
	for _, cmd := range strings.Split(rest, ",") {
		cmd = strings.TrimSpace(cmd)
		for sudoTag.MatchString(cmd) {
			cmd = strings.TrimSpace(sudoTag.ReplaceAllString(cmd, ""))
		}
		f := strings.Fields(cmd)
		if len(f) == 0 {
			continue
		}
		base := filepath.Base(f[0])
		if f[0] == "ALL" || rootCommands[base] || (base == "systemctl" && len(f) == 1) {
			return true
		}
	}
	return false
}

func isWebUser(spec string) bool {
	for _, u := range strings.Split(spec, ",") {
		if u == "www-data" || u == "%www-data" {
			return true
		}
	}
	return false
}

func (h host) rootService() []string {
	if !h.isFile(botUnit) {
		return nil
	}
	files := []string{botUnit}
	for _, e := range h.readDir(botUnit + ".d") {
		if strings.HasSuffix(e.Name(), ".conf") {
			files = append(files, botUnit+".d/"+e.Name())
		}
	}
	user, wd := "", ""
	for _, p := range files {
		data, _ := h.read(p)
		for key, val := range serviceKeys(data) {
			switch key {
			case "User":
				user = val
			case "WorkingDirectory":
				wd = val
			}
		}
	}
	if user != "" && user != "root" && user != "0" {
		return nil
	}
	wd = strings.TrimPrefix(wd, "-")
	if !filepath.IsAbs(wd) {
		return nil
	}
	fi, err := os.Stat(h.path(wd))
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o002 == 0 {
		return nil
	}
	return []string{botUnit, filepath.Clean(wd)}
}

func (h host) usbHits() []string {
	var hits []string
	for _, e := range h.readDir(udevDir) {
		if !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		p := udevDir + "/" + e.Name()
		if data, ok := h.read(p); ok && mentions(data, mountUSBName) {
			hits = append(hits, p)
		}
	}
	if h.isFile(mountUSB) {
		hits = append(hits, mountUSB)
	}
	return hits
}

func (h host) pppoe() bool {
	data, ok := h.read(crontabFile)
	return ok && len(PPPoECronLines(data)) > 0
}

func (h host) panelNetplanMoved() []string {
	var out []string
	for _, e := range h.readDir(netplanDir) {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "backup_") {
			continue
		}
		if p := netplanDir + "/" + e.Name() + "/" + panelNetplan; h.isFile(p) {
			out = append(out, p)
		}
	}
	return out
}

func anyUnit(units UnitState, names []string) bool {
	for _, u := range names {
		if enabled, active := units(u); enabled || active {
			return true
		}
	}
	return false
}

func execStartRuns(unit []byte, tail string) bool {
	for key, val := range serviceKeys(unit) {
		if key != "ExecStart" {
			continue
		}
		for _, f := range strings.Fields(val) {
			if f == tail || strings.HasSuffix(f, "/"+tail) {
				return true
			}
		}
	}
	return false
}

func serviceKeys(unit []byte) func(yield func(string, string) bool) {
	return func(yield func(string, string) bool) {
		inService := false
		for _, line := range joinContinued(unit) {
			t := strings.TrimSpace(line)
			if t == "" || t[0] == '#' || t[0] == ';' {
				continue
			}
			if t[0] == '[' {
				inService = t == "[Service]"
				continue
			}
			k, v, ok := strings.Cut(t, "=")
			if !inService || !ok {
				continue
			}
			if !yield(strings.TrimSpace(k), strings.TrimSpace(v)) {
				return
			}
		}
	}
}

func joinContinued(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

func mentions(data []byte, s string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && t[0] != '#' && strings.Contains(t, s) {
			return true
		}
	}
	return false
}

func hasLine(data []byte, s string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == s {
			return true
		}
	}
	return false
}

func hasField(data []byte, s string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		if slices.Contains(strings.Fields(t), s) {
			return true
		}
	}
	return false
}

type host struct{ root string }

func (h host) path(p string) string { return filepath.Join(h.root, p) }

func (h host) read(p string) ([]byte, bool) {
	data, err := os.ReadFile(h.path(p))
	return data, err == nil
}

func (h host) isFile(p string) bool {
	fi, err := os.Stat(h.path(p))
	return err == nil && fi.Mode().IsRegular()
}

func (h host) readDir(p string) []os.DirEntry {
	ents, _ := os.ReadDir(h.path(p))
	return ents
}

type pathSet map[string]bool

func (s *pathSet) add(ps ...string) {
	if *s == nil {
		*s = pathSet{}
	}
	for _, p := range ps {
		(*s)[p] = true
	}
}

func (s pathSet) list() []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
