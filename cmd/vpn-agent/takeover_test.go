package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
)

type tkFake struct {
	root   string
	calls  []string
	states map[string]takeover.UnitState
	known  bool
	cmds   [][]byte
	boot   string
	clock  time.Time
	codes  map[string]int
	chowns []string

	nftOut map[string]string
	nftErr map[string]string

	fail string

	journalSeen []bool
}

func (f *tkFake) note(call string) error {
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.HasPrefix(call, f.fail) {
		return errors.New("подделка: " + call)
	}
	return nil
}

func (f *tkFake) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *tkFake) sys() takeoverSys {
	return takeoverSys{
		root: f.root,
		systemctl: func(args ...string) error {
			f.journalSeen = append(f.journalSeen, fileExists(filepath.Join(f.root, takeoverJournalFile)))
			if err := f.note("systemctl " + strings.Join(args, " ")); err != nil {
				return err
			}

			if len(args) == 2 {
				st, ok := f.states[args[1]]
				if ok {
					switch args[0] {
					case "disable":
						st.Enabled = false
					case "mask":
						st.Masked, st.Enabled = true, false
					case "stop":
						st.Active = false
					case "start":
						st.Active = true
					}
					f.states[args[1]] = st
				}
			}
			return nil
		},
		units: func(names []string) (map[string]takeover.UnitState, bool) {
			if !f.known {
				return nil, false
			}
			out := map[string]takeover.UnitState{}
			for _, n := range names {
				if s, ok := f.states[n]; ok {
					out[n] = s
				}
			}
			return out, true
		},
		nft: func(stdin []byte, args ...string) ([]byte, error) {
			key := strings.Join(args, " ")
			if key == "-f -" {
				return nil, f.note("nft -f -: " + string(stdin))
			}
			if msg, bad := f.nftErr[key]; bad {
				return []byte(msg), errors.New("nft")
			}
			return []byte(f.nftOut[key]), nil
		},
		run: func(tool string, args ...string) ([]byte, int, error) {
			call := "run " + tool + " " + strings.Join(args, " ")
			if err := f.note(call); err != nil {
				return nil, 0, err
			}
			if tool == "poff" {
				f.cmds = nil
			}
			return []byte("ответ " + tool), f.codes[tool], nil
		},
		cmdlines: func() [][]byte { return f.cmds },
		bootID:   func() string { return f.boot },
		now:      func() time.Time { return f.clock },
		sleep:    func(d time.Duration) { f.clock = f.clock.Add(d) },
		home: func(args ...string) ([]byte, error) {
			var out, errOut bytes.Buffer
			if code := legacyHome(f.root, args, &out, &errOut); code != 0 {
				return nil, errors.New(strings.TrimSpace(errOut.String()))
			}
			return out.Bytes(), nil
		},
		cards: func() ([]netstatus.Interface, error) {
			return []netstatus.Interface{
				{Name: "ens2", MAC: "52:54:00:aa:00:02", Addresses: []string{"10.0.2.15/24"}},
				{Name: "ens3", MAC: "52:54:00:aa:00:03", Addresses: []string{"192.168.11.1/24"}},
			}, nil
		},
		lchown: func(p string, uid, gid int) error {
			f.chowns = append(f.chowns, fmt.Sprintf("%s %d:%d", strings.TrimPrefix(p, f.root), uid, gid))
			return nil
		},
		chmod: func(p string, mode os.FileMode) error {
			f.chowns = append(f.chowns, fmt.Sprintf("%s %o", strings.TrimPrefix(p, f.root), mode))
			return nil
		},
		spawn: func(fn func()) { fn() },
	}
}

func tkHome(user string) string { return "/home/" + user + "/vpn.sh" }

func tkRunner(f *tkFake) *takeoverRunner {
	return &takeoverRunner{sys: f.sys(), journalPath: takeoverJournalFile, asideDir: takeoverAsideDir,
		backupRoot: takeoverBackupRoot, limiter: takeoverPlanLimiter()}
}

var pppdCmdline = []byte("/usr/sbin/pppd\x00call\x00dsl-provider\x00")

const (
	tkCrontab = "SHELL=/bin/sh\n17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n" +
		"@reboot root sleep 20 && /usr/bin/pon dsl-provider\n" +
		"  * * * * * root pgrep -f 'pppd call dsl-provider' > /dev/null || /usr/bin/pon dsl-provider\n"
	tkSudoersStock = "Defaults\tenv_reset\nroot\tALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n"
	tkSudoersLines = "www-data ALL=(root) NOPASSWD: /usr/bin/id\nwww-data ALL=(ALL) NOPASSWD: ALL\nwww-data ALL=(ALL) NOPASSWD: /bin/systemctl\n"
	tkSysctl       = "net.ipv4.ip_forward=1\nnet.netfilter.nf_conntrack_max=262144\nnet.netfilter.nf_conntrack_udp_timeout_stream=120\n"
	tkRulesV4      = "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -i ens3 -o tun0 -j ACCEPT\nCOMMIT\n"
	tkScript       = "#!/bin/bash\n# vpn.sh v2.5.5\necho old\n"
)

func tkLegacyFiles() map[string]string {
	unit := func(prog string) string { return "[Service]\nExecStart=" + prog + "\nUser=root\n" }
	return map[string]string{
		legacyvpn.ScriptNetplan:                           "network:\n  version: 2\n  ethernets:\n    ens3:\n      addresses: [192.168.11.1/24]\n",
		"/etc/netplan/99-vpn-panel.yaml":                  "network:\n  version: 2\n",
		legacyvpn.UdevRule:                                "ACTION==\"add\", RUN+=\"/usr/local/bin/mount-usb.sh add %k\"\n",
		legacyvpn.MountUSB:                                "#!/bin/bash\n",
		"/etc/systemd/resolved.conf":                      "# Файл автоматически сгенерирован скриптом vpn.sh\n[Resolve]\n",
		legacyvpn.Crontab:                                 tkCrontab,
		legacyvpn.SysctlConf:                              tkSysctl,
		legacyvpn.Sudoers:                                 tkSudoersStock + tkSudoersLines + tkSudoersLines,
		legacyvpn.BotSudoers:                              "www-data ALL=NOPASSWD: /bin/systemctl start telegram_bot.service\n",
		legacyvpn.PPPoEPeer:                               "plugin rp-pppoe.so ens2\nuser \"office\"\n",
		legacyvpn.RulesV4:                                 tkRulesV4,
		legacyvpn.OpenVPNConf:                             "client\ndev tun0\n",
		legacyvpn.OpenVPNDefault:                          "#AUTOSTART=\"none\"\nAUTOSTART=\"all\"\n",
		legacyvpn.WebCrontab:                              "* * * * * /usr/bin/python3 /var/www/html/api/update_network_metrics.py\n",
		"/etc/systemd/system/ping_daemon.service":         unit("/usr/local/bin/ping_daemon.sh"),
		"/etc/systemd/system/vpn_mtu_daemon.service":      unit("/usr/local/bin/vpn_mtu_daemon.sh"),
		"/etc/systemd/system/telegram_bot.service":        unit("/var/www/html/bot_source/venv/bin/python /var/www/html/bot_source/bot.py"),
		"/etc/systemd/system/update_metrics.service":      unit("/usr/bin/python3 /var/www/html/api/update_metrics_daemon.py"),
		"/etc/systemd/system/network_load.service":        unit("/usr/bin/python3 /var/www/html/api/update_network_load.py"),
		"/etc/systemd/system/home_metrics_daemon.service": unit("/usr/bin/python3 /var/www/html/api/home_metrics_daemon.py"),
		"/usr/local/bin/ping_daemon.sh":                   "#!/bin/bash\n",
		"/usr/local/bin/vpn_mtu_daemon.sh":                "#!/bin/bash\n",
		"/etc/default/isc-dhcp-server":                    "INTERFACESv4=\"ens3\"\n",
		tkHome("office"):                                  tkScript,
	}
}

func tkStandUnits() map[string]takeover.UnitState {
	on := takeover.UnitState{Enabled: true, Active: true}
	etcOn := takeover.UnitState{Enabled: true, Active: true, FileInEtc: true}
	return map[string]takeover.UnitState{
		"apache2.service":              on,
		"isc-dhcp-server.service":      on,
		"shellinabox.service":          on,
		"cron.service":                 on,
		"netfilter-persistent.service": on,
		"openvpn@client1.service":      on,
		"openvpn.service":              {Enabled: true},
		"ping_daemon.service":          etcOn,
		"vpn_mtu_daemon.service":       etcOn,
		"telegram_bot.service":         {Enabled: true, FileInEtc: true},
		"update_metrics.service":       etcOn,
		"network_load.service":         etcOn,
		"home_metrics_daemon.service":  etcOn,
	}
}

func tkRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o640); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib/vpn-panel"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	return root
}

const tkForwardChainJSON = `{"nftables":[{"metainfo":{"json_schema_version":1}},
{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":13,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"ens3"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"tun0"}},{"accept":null}]}}]}`

func tkStand(t *testing.T) (*tkFake, *takeoverRunner) {
	t.Helper()
	f := &tkFake{
		root: tkRoot(t, tkLegacyFiles()), states: tkStandUnits(), known: true,
		cmds: [][]byte{pppdCmdline, []byte("/usr/sbin/cron\x00-f\x00")},
		boot: "boot-1", clock: time.Date(2026, 10, 20, 10, 15, 0, 0, time.UTC),
		codes:  map[string]int{"poff": 1},
		nftOut: map[string]string{"-j -a list chain ip filter FORWARD": tkForwardChainJSON},
	}
	return f, tkRunner(f)
}

func tkPlan(t *testing.T, r *takeoverRunner) takeover.Plan {
	t.Helper()
	p, err := r.plan([]string{"ens3"}, []string{"ens2", "ens3"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tkIDs(p takeover.Plan) []string {
	out := make([]string, 0, len(p.Items))
	for _, it := range p.Items {
		out = append(out, it.ID)
	}
	return out
}

func readText(t *testing.T, root, p string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, p)) //nolint:gosec
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return string(data)
}

func backupDir(t *testing.T, r *takeoverRunner) string {
	t.Helper()
	j, ok, err := r.readJournal()
	if err != nil || !ok || j.Backup == "" {
		t.Fatalf("журнал без каталога копии: %v %v %+v", ok, err, j)
	}
	return j.Backup
}

func TestTakeoverPlanOnLegacyRoot(t *testing.T) {
	_, r := tkStand(t)
	p := tkPlan(t, r)
	want := []string{"legacy.dhcp", "legacy.forward", "legacy.daemons", "legacy.netplan", "legacy.pppoe",
		"legacy.sudo", "legacy.sysctl", "legacy.terminal", "legacy.tunnel", "legacy.web", "legacy.usb", "legacy.script"}
	if got := tkIDs(p); !slices.Equal(got, want) {
		t.Fatalf("пункты плана:\n есть %v\n ждём %v", got, want)
	}
	if len(p.Digest) == 0 {
		t.Fatal("план без отпечатка")
	}
	if sel, err := p.Select([]string{"legacy.script", "нет.такого"}); err == nil || len(sel.Items) != 0 {
		t.Fatal("чужой идентификатор принят")
	}
}

func TestTakeoverPlanOnCleanRoot(t *testing.T) {
	f := &tkFake{root: tkRoot(t, map[string]string{"/etc/netplan/99-vpn-panel.yaml": "network:\n  version: 2\n"}), known: true}
	p := tkPlan(t, tkRunner(f))
	if len(p.Items) != 0 {
		t.Fatalf("на чистой машине план не пуст: %v", tkIDs(p))
	}
}

func TestTakeoverBeginWritesJournalFirst(t *testing.T) {
	f, r := tkStand(t)
	f.fail = "systemctl stop cron.service"
	_, err := r.begin(tkPlan(t, r))
	if err == nil {
		t.Fatal("ошибка шага 1 не вернулась")
	}
	if len(f.journalSeen) == 0 || !f.journalSeen[0] {
		t.Fatal("журнала не было на диске при первом вызове systemctl")
	}
	if fileExists(filepath.Join(f.root, takeoverJournalFile)) {
		t.Fatal("после отказа журнал остался")
	}
	if got := readText(t, f.root, legacyvpn.ScriptNetplan); !strings.Contains(got, "192.168.11.1/24") {
		t.Fatal("файл Netplan старого скрипта не вернулся на место")
	}
	if ents, _ := os.ReadDir(filepath.Join(f.root, takeoverAsideDir)); len(ents) != 0 {
		t.Fatalf("в стороне остались файлы: %d", len(ents))
	}
	if f.count("systemctl mask") != 0 || f.count("systemctl disable") != 0 {
		t.Fatalf("шаг 1 выключал службы: %v", f.calls)
	}
}

func TestTakeoverAsideKeepsModeAndOwner(t *testing.T) {
	f, r := tkStand(t)
	p := filepath.Join(f.root, legacyvpn.ScriptNetplan)
	if err := os.Chmod(p, 0o604); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	j, err := r.begin(tkPlan(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if fileExists(p) {
		t.Fatal("файл не ушёл в сторону")
	}
	if len(j.Aside) != 1 || j.Aside[0].Mode != 0o604 || j.Aside[0].UID != os.Getuid() {
		t.Fatalf("запись о файле в стороне: %+v", j.Aside)
	}
	if err := r.restoreAside(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o604 {
		t.Fatalf("файл вернулся не с теми правами: %v %v", fi, err)
	}
	if err := r.restoreAside(); err != nil {
		t.Fatalf("повторный возврат: %v", err)
	}
	j2, _, _ := r.readJournal()
	if len(j2.Aside) != 0 {
		t.Fatalf("журнал помнит возвращённый файл: %+v", j2.Aside)
	}
}

func TestTakeoverFullRun(t *testing.T) {
	f, r := tkStand(t)
	plan := tkPlan(t, r)
	if _, err := r.begin(plan); err != nil {
		t.Fatal(err)
	}
	if f.count("run poff") != 1 || f.count("systemctl stop cron.service") != 1 || f.count("systemctl stop openvpn@client1.service") != 1 {
		t.Fatalf("шаг 1: %v", f.calls)
	}
	if st := r.status(); st.State != "window" {
		t.Fatalf("этап после шага 1: %+v", st)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	done, err := r.finish()
	if err != nil || !done {
		t.Fatalf("шаг 3: done=%v err=%v\n%v", done, err, strings.Join(f.calls, "\n"))
	}
	root, bk := f.root, backupDir(t, r)
	if !strings.HasPrefix(bk, takeoverBackupRoot+"/takeover-20261020T") {
		t.Fatalf("каталог копии: %s", bk)
	}

	for _, p := range []string{legacyvpn.ScriptNetplan, legacyvpn.OpenVPNConf, legacyvpn.RulesV4, legacyvpn.PPPoEPeer,
		legacyvpn.UdevRule, legacyvpn.MountUSB, "/etc/systemd/system/ping_daemon.service", "/usr/local/bin/ping_daemon.sh",
		legacyvpn.WebCrontab, legacyvpn.BotSudoers} {
		if !fileExists(filepath.Join(root, bk, p)) {
			t.Errorf("в копии нет %s", p)
		}
		if fileExists(filepath.Join(root, p)) {
			t.Errorf("оригинал %s остался", p)
		}
	}

	for _, p := range []string{legacyvpn.Sudoers, legacyvpn.Crontab, legacyvpn.SysctlConf, legacyvpn.OpenVPNDefault} {
		if !fileExists(filepath.Join(root, bk, p)) {
			t.Errorf("в копии нет %s", p)
		}
	}
	if got := readText(t, root, legacyvpn.Sudoers); got != tkSudoersStock {
		t.Errorf("sudoers после захвата:\n%s", got)
	}
	if got := readText(t, root, legacyvpn.Crontab); strings.Contains(got, "pon") || !strings.Contains(got, "run-parts") {
		t.Errorf("crontab после захвата:\n%s", got)
	}
	if got := readText(t, root, legacyvpn.SysctlConf); !strings.Contains(got, "#net.ipv4.ip_forward=1") ||
		!strings.Contains(got, "#net.netfilter.nf_conntrack_udp_timeout_stream=120") || !strings.Contains(got, "\nnet.netfilter.nf_conntrack_max=262144") {
		t.Errorf("sysctl после захвата:\n%s", got)
	}
	if got := readText(t, root, legacyvpn.OpenVPNDefault); !strings.Contains(got, "AUTOSTART=\"none\"") || strings.Contains(got, "\"all\"") {
		t.Errorf("default/openvpn после захвата:\n%s", got)
	}

	if got := readText(t, root, tkHome("office")); got != legacyStubScript {
		t.Errorf("заглушка:\n%s", got)
	}
	if fi, _ := os.Stat(filepath.Join(root, tkHome("office"))); fi == nil || fi.Mode().Perm() != legacyStubMode {
		t.Errorf("права заглушки: %v", fi)
	}
	if got := readText(t, root, bk+tkHome("office")); got != tkScript {
		t.Errorf("копия скрипта:\n%s", got)
	}

	var manifest []takeoverCopy
	if err := json.Unmarshal([]byte(readText(t, root, bk+"/"+takeoverManifestName)), &manifest); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, m := range manifest {
		paths[m.Path] = true
	}
	for _, p := range []string{legacyvpn.ScriptNetplan, legacyvpn.Sudoers, tkHome("office"), legacyvpn.RulesV4} {
		if !paths[p] {
			t.Errorf("в описи копии нет %s", p)
		}
	}

	for _, want := range []string{"systemctl disable isc-dhcp-server.service", "systemctl mask isc-dhcp-server.service",
		"systemctl stop isc-dhcp-server.service", "systemctl disable apache2.service", "systemctl stop apache2.service",
		"systemctl mask shellinabox.service", "systemctl disable netfilter-persistent.service", "systemctl daemon-reload",
		"systemctl start cron.service", "run udevadm control --reload-rules", "run visudo -c -f "} {
		if f.count(want) == 0 {
			t.Errorf("не было вызова %q", want)
		}
	}
	if i, j := slices.Index(f.calls, "systemctl disable apache2.service"), slices.Index(f.calls, "systemctl stop apache2.service"); i > j {
		t.Error("stop раньше disable")
	}

	wantTx := "nft -f -: flush chain ip filter FORWARD\nadd chain ip filter FORWARD { type filter hook forward priority 0; policy accept; }\n"
	if !slices.Contains(f.calls, wantTx) {
		t.Errorf("транзакция nft:\n%v", f.calls)
	}

	if !slices.Equal(f.chowns, []string{"/etc/openvpn 0:0", "/etc/openvpn 755"}) {
		t.Errorf("владелец каталога канала: %v", f.chowns)
	}
	if st := r.status(); st.State != "done" || st.Failed != 0 || !slices.Equal(st.Residue, []string{"resolved_header"}) {
		t.Errorf("итог: %+v", st)
	}
	if res, ok := r.taken(); !ok || len(res) != 1 {
		t.Errorf("taken: %v %v", res, ok)
	}

	n := len(f.calls)
	if done, err := r.finish(); err != nil || !done || len(f.calls) != n {
		t.Fatalf("повторный проход: done=%v err=%v, новых вызовов %d", done, err, len(f.calls)-n)
	}
}

func TestTakeoverFinishResumesAfterFailure(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	f.fail = "systemctl mask shellinabox.service"
	done, err := r.finish()
	if err != nil || done {
		t.Fatalf("проход с отказом: done=%v err=%v", done, err)
	}
	st := r.status()
	if st.State != "partial" || st.Failed != 1 {
		t.Fatalf("после отказа: %+v", st)
	}
	if f.count("systemctl stop shellinabox.service") != 0 {
		t.Fatal("пункт пошёл дальше после отказа")
	}
	if f.count("systemctl stop apache2.service") != 1 || !fileExists(filepath.Join(f.root, backupDir(t, r), legacyvpn.RulesV4)) {
		t.Fatal("остальные пункты не шли")
	}
	f.fail = ""
	n := len(f.calls)
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("доделка: done=%v err=%v", done, err)
	}
	if f.count("systemctl mask shellinabox.service") != 2 || f.count("systemctl stop shellinabox.service") != 1 {
		t.Fatalf("доделка повторила не то: %v", f.calls[n:])
	}
	if f.count("systemctl stop apache2.service") != 1 {
		t.Fatal("доделка повторила сделанный пункт")
	}
	if r.status().State != "done" {
		t.Fatalf("итог: %+v", r.status())
	}
}

func TestTakeoverBootChangeRepeatsTemporary(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	f.fail = "systemctl start cron.service"
	if done, _ := r.finish(); done {
		t.Fatal("проход с отказом не может быть полным")
	}
	stops, poffs := f.count("systemctl stop cron.service"), f.count("run poff")
	f.fail, f.boot = "", "boot-2"
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("доделка в новой загрузке: done=%v err=%v", done, err)
	}
	if f.count("systemctl stop cron.service") != stops+1 || f.count("run poff") != poffs+1 {
		t.Fatalf("временные операции не повторились: stop %d→%d, poff %d→%d", stops, f.count("systemctl stop cron.service"), poffs, f.count("run poff"))
	}
	if n := f.count("run visudo"); n != 1 {
		t.Fatalf("постоянная правка повторилась: visudo %d", n)
	}
}

func TestTakeoverUndoAfterRebootStartsNothing(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	f.boot = "boot-2"
	n := len(f.calls)
	r.undoUnits()
	for _, c := range f.calls[n:] {
		if strings.HasPrefix(c, "systemctl start") || strings.HasPrefix(c, "run pon") {
			t.Fatalf("после перезагрузки запущено: %s", c)
		}
	}
	if !fileExists(filepath.Join(f.root, legacyvpn.ScriptNetplan)) || fileExists(filepath.Join(f.root, takeoverJournalFile)) {
		t.Fatal("файлы не вернулись или журнал остался")
	}
}

func TestTakeoverUndoSameBootStartsStopped(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	r.undoUnits()
	for _, want := range []string{"run pon dsl-provider", "systemctl start cron.service", "systemctl start openvpn@client1.service"} {
		if f.count(want) != 1 {
			t.Errorf("откат окна без %q: %v", want, f.calls)
		}
	}
	if i, j := slices.Index(f.calls, "run pon dsl-provider"), slices.Index(f.calls, "systemctl start cron.service"); i > j {
		t.Error("cron запущен раньше pon: сторож cron поднял бы второй pppd")
	}
	if f.count("systemctl start openvpn.service") != 0 {
		t.Error("запущена служба, которая не работала до шага 1")
	}
}

func TestTakeoverPonSkipsLivePppd(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	f.cmds = [][]byte{pppdCmdline}
	r.undoUnits()
	if f.count("run pon") != 0 {
		t.Fatal("pon при живом pppd")
	}

	f2, r2 := tkStand(t)
	if _, err := r2.begin(tkPlan(t, r2)); err != nil {
		t.Fatal(err)
	}
	f2.cmds = [][]byte{[]byte("/bin/sh\x00-c\x00pgrep -f 'pppd call dsl-provider'\x00")}
	r2.undoUnits()
	if f2.count("run pon") != 1 {
		t.Fatal("pon не вызван, хотя pppd нет")
	}
}

func TestTakeoverWaitGoneTimesOut(t *testing.T) {
	f, r := tkStand(t)
	f.cmds = [][]byte{pppdCmdline}
	start := f.clock
	if err := r.waitGone(pppdWait()); err == nil {
		t.Fatal("ожидание pppd не кончилось ошибкой")
	}
	if f.clock.Sub(start) < takeoverWaitGone {
		t.Fatalf("сдались раньше срока: %v", f.clock.Sub(start))
	}
	f.cmds = nil
	if err := r.waitGone(pppdWait()); err != nil {
		t.Fatal(err)
	}
}

func TestTakeoverNftWordsAreChecked(t *testing.T) {
	f, r := tkStand(t)
	op := takeover.Op{Kind: takeover.OpForwardPolicy, Family: "ip", Table: "filter", Chain: "FWD; flush ruleset"}
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: op}); err == nil {
		t.Fatal("имя с точкой с запятой принято")
	}
	f.nftOut["-j -t list ruleset"] = `{"nftables":[{"chain":{"family":"ip","table":"t","name":"c","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"ip","table":"bad name","name":"c","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}]}`
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: takeover.Op{Kind: takeover.OpForwardPolicy}}); err == nil {
		t.Fatal("имя с пробелом из живого набора принято")
	}
	if f.count("nft -f -") != 0 {
		t.Fatalf("транзакция ушла: %v", f.calls)
	}
}

func TestTakeoverRecoverOnStart(t *testing.T) {

	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	r.recoverOnStart(true)
	if !fileExists(filepath.Join(f.root, legacyvpn.ScriptNetplan)) || r.status().State != "none" {
		t.Fatalf("окно открыто: %+v", r.status())
	}

	f2, r2 := tkStand(t)
	if _, err := r2.begin(tkPlan(t, r2)); err != nil {
		t.Fatal(err)
	}
	r2.recoverOnStart(false)
	if r2.status().State != "done" || fileExists(filepath.Join(f2.root, legacyvpn.RulesV4)) {
		t.Fatalf("окна нет: %+v", r2.status())
	}

	f3, r3 := tkStand(t)
	r3.recoverOnStart(false)
	if len(f3.calls) != 0 {
		t.Fatalf("без журнала были вызовы: %v", f3.calls)
	}
}

func TestTakeoverBrokenJournalIsNotExecuted(t *testing.T) {
	f, r := tkStand(t)
	if err := os.WriteFile(filepath.Join(f.root, takeoverJournalFile), []byte(`{"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.recoverOnStart(false)
	if done, err := r.finish(); err == nil || done {
		t.Fatal("чужая схема журнала исполнена")
	}
	if len(f.calls) != 0 || r.units() != nil {
		t.Fatalf("по негодному журналу что-то сделано: %v", f.calls)
	}
}

func TestTakeoverUnitsAndBeginTwice(t *testing.T) {
	_, r := tkStand(t)
	if r.units() != nil {
		t.Fatal("без журнала юниты есть")
	}
	plan := tkPlan(t, r)
	if _, err := r.begin(plan); err != nil {
		t.Fatal(err)
	}
	if u := r.units(); !slices.Contains(u, "isc-dhcp-server.service") || !slices.Contains(u, "cron.service") {
		t.Fatalf("юниты журнала: %v", u)
	}
	if _, err := r.begin(plan); err == nil {
		t.Fatal("второй шаг 1 при открытом журнале")
	}
}

func TestTakeoverWithoutSystemdAnswer(t *testing.T) {
	f, r := tkStand(t)
	f.known = false
	p := tkPlan(t, r)
	for _, it := range p.Items {
		for _, op := range it.Step1 {
			if op.Kind != takeover.OpAside {
				t.Fatalf("шаг 1 без systemd трогает %s: %+v", it.ID, op)
			}
		}
	}
	if _, err := r.begin(p); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("шаг 3 без systemd: done=%v err=%v", done, err)
	}
}

func TestTakeoverSudoersRejectedByVisudo(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	f.codes["visudo"] = 1
	before := readText(t, f.root, legacyvpn.Sudoers)
	if done, _ := r.finish(); done {
		t.Fatal("проход полный при отказе visudo")
	}
	if got := readText(t, f.root, legacyvpn.Sudoers); got != before {
		t.Fatal("sudoers изменён, хотя visudo отверг")
	}
	ents, _ := os.ReadDir(filepath.Join(f.root, "etc"))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".vpn-panel-tmp") {
			t.Fatalf("после отказа остался временный файл %s", e.Name())
		}
	}
	f.codes["visudo"] = 0
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("доделка: done=%v err=%v", done, err)
	}
	if got := readText(t, f.root, legacyvpn.Sudoers); got != tkSudoersStock {
		t.Fatalf("sudoers после доделки:\n%s", got)
	}
}

func TestTakeoverForwardPruneKeepsDocker(t *testing.T) {
	f, r := tkStand(t)
	f.nftOut["-j -a list chain ip filter FORWARD"] = `{"nftables":[
{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":10,"expr":[{"jump":{"target":"DOCKER-USER"}}]}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":11,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"docker0"}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":12,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":{"set":["br-0123456789ab","ens9"]}}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":13,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"ens4"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"reject":{"type":"icmp","expr":"net-unreachable"}}]}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":14,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"accept":null}]}}]}`
	op := takeover.Op{Kind: takeover.OpForwardPrune, Family: "ip", Table: "filter", Chain: "FORWARD"}
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: op}); err != nil {
		t.Fatal(err)
	}
	want := "nft -f -: delete rule ip filter FORWARD handle 13\ndelete rule ip filter FORWARD handle 14\n" +
		"add chain ip filter FORWARD { type filter hook forward priority 0; policy accept; }\n"
	if !slices.Contains(f.calls, want) {
		t.Fatalf("транзакция:\n%v", f.calls)
	}
}

func TestTakeoverForwardAcceptWithoutChain(t *testing.T) {
	f, r := tkStand(t)
	f.nftErr = map[string]string{"-j -a list chain ip filter FORWARD": "Error: No such file or directory\nlist chain ip filter FORWARD"}
	op := takeover.Op{Kind: takeover.OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"}
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: op}); err != nil {
		t.Fatal(err)
	}
	if f.count("nft -f -") != 0 {
		t.Fatal("транзакция без цепочки")
	}

	f.nftErr["-j -a list chain ip filter FORWARD"] = "Error: syntax error"
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: op}); err == nil {
		t.Fatal("ошибка nft проглочена")
	}
}

func TestTakeoverForwardPolicyAllForeign(t *testing.T) {
	f, r := tkStand(t)
	f.nftOut["-j -t list ruleset"] = `{"nftables":[
{"chain":{"family":"inet","table":"vpn_panel","name":"forward","handle":1,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":3}},
{"chain":{"family":"inet","table":"admin","name":"fwd","handle":4,"type":"filter","hook":"forward","prio":-10,"policy":"drop"}},
{"chain":{"family":"bridge","table":"nat","name":"fwd","handle":5,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"admin","name":"in","handle":6,"type":"filter","hook":"input","prio":0,"policy":"drop"}}]}`
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: takeover.Op{Kind: takeover.OpForwardPolicy}}); err != nil {
		t.Fatal(err)
	}
	want := "nft -f -: add chain inet admin fwd { type filter hook forward priority -10; policy accept; }\n"
	if !slices.Contains(f.calls, want) {
		t.Fatalf("транзакция:\n%v", f.calls)
	}
}

func TestTakeoverDHCPHolders(t *testing.T) {
	root := t.TempDir()
	procFixture(t, root, "udp", dhcpdLine, "0::/system.slice/isc-dhcp-server.service", "dhcpd")
	writeFixture(t, root, "etc/default/isc-dhcp-server", "INTERFACESv4=\"ens3\"\n")
	owners := dhcpSocketOwners(root)
	if len(owners) != 1 || owners[0].unit != "isc-dhcp-server.service" {
		t.Fatalf("владельцы сокета: %+v", owners)
	}
	none := func(string) (takeover.UnitState, bool) { return takeover.UnitState{}, false }
	cards := []netstatus.Interface{{Name: "ens3", Addresses: []string{"192.168.11.1/24"}}}
	if got := dhcpHolders(root, []string{"ens3"}, cards, owners, none); !slices.Equal(got, []string{"isc-dhcp-server.service"}) {
		t.Fatalf("сокет на всех адресах с картой офиса в конфиге: %v", got)
	}
	if got := dhcpHolders(root, []string{"ens4"}, cards, owners, none); len(got) != 0 {
		t.Fatalf("служба на другой карте попала в план: %v", got)
	}

	enabled := func(u string) (takeover.UnitState, bool) {
		return takeover.UnitState{Enabled: u == "isc-dhcp-server.service"}, true
	}
	if got := dhcpHolders(root, []string{"ens3"}, cards, nil, enabled); !slices.Equal(got, []string{"isc-dhcp-server.service"}) {
		t.Fatalf("включённая служба: %v", got)
	}
}

func TestParseTakeoverUnits(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/systemd/system/ping_daemon.service", "[Service]\n")
	out := "Id=apache2.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\nSubState=running\nFragmentPath=/lib/systemd/system/apache2.service\n\n" +
		"Id=ping_daemon.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=activating\nSubState=auto-restart\nFragmentPath=/etc/systemd/system/ping_daemon.service\n\n" +
		"Id=ufw.service\nLoadState=masked\nUnitFileState=masked\nActiveState=inactive\nSubState=dead\nFragmentPath=/dev/null\n\n" +
		"Id=nope.service\nLoadState=not-found\nUnitFileState=\nActiveState=inactive\nSubState=dead\nFragmentPath=\n"
	got := parseTakeoverUnits(root, out)
	if _, ok := got["nope.service"]; ok || len(got) != 3 {
		t.Fatalf("незнакомый юнит в ответе: %+v", got)
	}
	if s := got["apache2.service"]; !s.Enabled || !s.Active || s.FileInEtc || s.Masked {
		t.Fatalf("apache2: %+v", s)
	}
	if s := got["ping_daemon.service"]; !s.FileInEtc || !s.Active {
		t.Fatalf("ping_daemon: %+v", s)
	}
	if s := got["ufw.service"]; !s.Masked || s.Enabled {
		t.Fatalf("ufw: %+v", s)
	}
}

func TestTakeoverTextEdits(t *testing.T) {
	drop := dropLines([]string{"a=1", "b = 2"})
	if got := string(drop([]byte("x\n  a=1 \nb = 2\na=1\ny\n"))); got != "x\ny\n" {
		t.Fatalf("drop_lines: %q", got)
	}
	comment := commentKeys([]string{"net.ipv4.ip_forward"})
	in := "net.ipv4.ip_forward=1\n-net/ipv4/ip_forward = 1\n#net.ipv4.ip_forward=0\nnet.ipv4.other=1\n"
	want := "#net.ipv4.ip_forward=1\n#-net/ipv4/ip_forward = 1\n#net.ipv4.ip_forward=0\nnet.ipv4.other=1\n"
	if got := string(comment([]byte(in))); got != want {
		t.Fatalf("comment_keys:\n%s", got)
	}
	if got := string(comment([]byte(want))); got != want {
		t.Fatal("повтор comment_keys меняет файл")
	}
}
