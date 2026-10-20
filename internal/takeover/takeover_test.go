package takeover

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

func stop(u string) Op    { return Op{Kind: OpStop, Unit: u} }
func start(u string) Op   { return Op{Kind: OpStart, Unit: u} }
func disable(u string) Op { return Op{Kind: OpDisable, Unit: u} }
func mask(u string) Op    { return Op{Kind: OpMask, Unit: u} }
func backup(p string) Op  { return Op{Kind: OpBackup, Path: p} }
func exec(c string) Op    { return Op{Kind: OpExec, Command: c} }

var reload = exec(CmdDaemonReload)

func hasOp(ops []Op, op Op) bool {
	return slices.ContainsFunc(ops, func(o Op) bool { return reflect.DeepEqual(o, op) })
}

func daemonOps(name string) []Op {
	u := name + ".service"
	return []Op{disable(u), stop(u), backup("/etc/systemd/system/" + u)}
}

func cat(parts ...[]Op) []Op {
	var out []Op
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func standEnv(t *testing.T, units unitMap) Env {
	root := build(t, with(common, vpnMode))
	env := legacyEnv(root, units)
	env.DHCPUnits = []string{"isc-dhcp-server"}
	env.ForwardSources = []string{"netfilter-persistent"}
	env.ForwardBootFiles = []string{legacyvpn.SysctlConf}
	env.HomeScripts = []string{homeScript}
	return env
}

func TestLegacyStand(t *testing.T) {
	p := Build(standEnv(t, standUnits))
	wantIDs := []string{
		"legacy.dhcp", "legacy.forward",
		"legacy.daemons", "legacy.netplan", "legacy.pppoe", "legacy.sudo", "legacy.sysctl",
		"legacy.terminal", "legacy.tunnel", "legacy.web",
		"legacy.usb", "legacy.script",
	}
	if got := ids(p); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("пункты %v\nожидали   %v", got, wantIDs)
	}
	poff := []Op{exec(CmdPoff), {Kind: OpWaitGone, Argv0: "pppd", Args: []string{"call", "dsl-provider"}}}
	tests := []struct {
		id                 string
		step1, step3, undo []Op
	}{
		{id: "legacy.dhcp", step3: []Op{disable("isc-dhcp-server.service"), mask("isc-dhcp-server.service"), stop("isc-dhcp-server.service")}},
		{id: "legacy.forward", step3: []Op{
			stop("vpn_mtu_daemon.service"),
			disable("netfilter-persistent.service"), mask("netfilter-persistent.service"),
			backup(legacyvpn.RulesV4),
			{Kind: OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"},
		}},
		{id: "legacy.daemons", step3: cat(
			daemonOps("home_metrics_daemon"), daemonOps("network_load"), daemonOps("ping_daemon"),
			daemonOps("telegram_bot"), daemonOps("update_metrics"), daemonOps("vpn_mtu_daemon"),
			[]Op{reload, backup("/usr/local/bin/ping_daemon.sh"), backup("/usr/local/bin/vpn_mtu_daemon.sh"), backup(legacyvpn.WebCrontab)},
		)},
		{id: "legacy.netplan",
			step1: []Op{{Kind: OpAside, Path: legacyvpn.ScriptNetplan}},
			step3: []Op{backup(legacyvpn.ScriptNetplan)}},
		{id: "legacy.pppoe",
			step1: cat([]Op{stop("cron.service")}, poff),
			step3: cat(
				[]Op{stop("cron.service"), {Kind: OpDropLines, Path: legacyvpn.Crontab, Lines: []string{cronMinute, cronReboot}}},
				poff,
				[]Op{backup(legacyvpn.PPPoEPeer), start("cron.service")}),
			undo: []Op{exec(CmdPon), start("cron.service")}},
		{id: "legacy.sudo", step3: []Op{
			{Kind: OpSudoers, Path: legacyvpn.Sudoers, Lines: []string{
				"www-data ALL=(ALL) NOPASSWD: /bin/systemctl",
				"www-data ALL=(ALL) NOPASSWD: ALL",
				"www-data ALL=(root) NOPASSWD: /usr/bin/id",
			}},
			backup(legacyvpn.BotSudoers),
		}},
		{id: "legacy.sysctl", step3: []Op{{Kind: OpCommentKeys, Path: legacyvpn.SysctlConf,
			Keys: []string{"net.ipv4.ip_forward", "net.netfilter.nf_conntrack_udp_timeout_stream"}}}},
		{id: "legacy.terminal", step3: []Op{disable("shellinabox.service"), mask("shellinabox.service"), stop("shellinabox.service")}},
		{id: "legacy.tunnel",
			step1: []Op{stop("openvpn@client1.service"), stop("openvpn.service")},
			step3: []Op{
				disable("openvpn@client1.service"), mask("openvpn@client1.service"), stop("openvpn@client1.service"),
				disable("openvpn.service"), mask("openvpn.service"), stop("openvpn.service"),
				backup(legacyvpn.OpenVPNConf),
				{Kind: OpSetKey, Path: legacyvpn.OpenVPNDefault, Key: "AUTOSTART", Value: "none"},
				{Kind: OpChownRoot, Path: legacyvpn.OpenVPNDir},
			},

			undo: []Op{start("openvpn@client1.service")}},
		{id: "legacy.web", step3: []Op{disable("apache2.service"), stop("apache2.service")}},
		{id: "legacy.usb", step3: []Op{backup(legacyvpn.UdevRule), backup(legacyvpn.MountUSB), exec(CmdUdevReload)}},
		{id: "legacy.script", step3: []Op{{Kind: OpStub, Path: homeScript}}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			it := find(t, p, tc.id)
			if !reflect.DeepEqual(it.Step1, tc.step1) {
				t.Errorf("шаг 1\nполучено %+v\nожидали  %+v", it.Step1, tc.step1)
			}
			if !reflect.DeepEqual(it.Step3, tc.step3) {
				t.Errorf("шаг 3\nполучено %+v\nожидали  %+v", it.Step3, tc.step3)
			}
			if !reflect.DeepEqual(it.Undo, tc.undo) {
				t.Errorf("откат\nполучено %+v\nожидали  %+v", it.Undo, tc.undo)
			}
			if !it.Checked || it.Locked || it.Title == "" || it.Found == "" || len(it.Support) == 0 {
				t.Errorf("пункт %+v", it)
			}
		})
	}
}

func TestLegacyDirect(t *testing.T) {
	root := build(t, with(common, directMode))
	units := unitMap{
		"isc-dhcp-server.service":      on,
		"cron.service":                 on,
		"netfilter-persistent.service": on,
	}
	env := legacyEnv(root, units)
	env.DHCPUnits = []string{"isc-dhcp-server"}
	p := Build(env)
	want := []string{"legacy.dhcp", "legacy.forward", "legacy.netplan", "legacy.sysctl", "legacy.usb"}
	if got := ids(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("пункты %v, ожидали %v", got, want)
	}
	fwd := find(t, p, "legacy.forward")
	if hasOp(fwd.Step3, stop("vpn_mtu_daemon.service")) {
		t.Errorf("демона подстройки канала нет, а его останавливают: %+v", fwd.Step3)
	}
	if sc := find(t, p, "legacy.sysctl").Step3[0].Keys; !reflect.DeepEqual(sc, []string{"net.ipv4.ip_forward", "net.netfilter.nf_conntrack_udp_timeout_stream"}) {
		t.Errorf("ключи %v", sc)
	}
}

func TestLegacyWithoutSystemd(t *testing.T) {
	env := standEnv(t, nil)
	env.DHCPUnits = nil
	p := Build(env)
	got := ids(p)
	for _, id := range []string{"legacy.web", "legacy.terminal", "legacy.dhcp"} {
		if slices.Contains(got, id) {
			t.Errorf("%s без ответа systemd: %v", id, got)
		}
	}
	for _, id := range []string{"legacy.daemons", "legacy.tunnel", "legacy.forward", "legacy.pppoe", "legacy.netplan"} {
		if !slices.Contains(got, id) {
			t.Errorf("%s опознан по файлам, а его нет: %v", id, got)
		}
	}
	for _, id := range []string{"legacy.tunnel", "legacy.pppoe"} {
		if it := find(t, p, id); it.Step1 != nil || it.Undo != nil {
			t.Errorf("%s: окно без ответа systemd трогает юниты: %+v %+v", id, it.Step1, it.Undo)
		}
	}
	if tun := find(t, p, "legacy.tunnel").Step3; !hasOp(tun, mask("openvpn@client1.service")) {
		t.Errorf("после подтверждения канал не выключается: %+v", tun)
	}
	fwd := find(t, p, "legacy.forward").Step3
	if !hasOp(fwd, mask("netfilter-persistent.service")) {
		t.Errorf("сохранённые правила есть, а службу восстановления не выключают: %+v", fwd)
	}
	pppoe := find(t, p, "legacy.pppoe")
	if !reflect.DeepEqual(pppoe.Step3[len(pppoe.Step3)-1], start("cron.service")) {
		t.Errorf("cron не возвращается: %+v", pppoe.Step3)
	}

	known := Build(standEnv(t, standUnits))
	if find(t, known, "legacy.tunnel").Step1 == nil || find(t, known, "legacy.pppoe").Step1 == nil {
		t.Error("с ответом systemd окно ничего не останавливает")
	}
}

func TestDockerAndVM(t *testing.T) {
	tests := []struct {
		name       string
		docker, vm bool
		want       OpKind
		note       string
	}{
		{name: "Docker", docker: true, want: OpForwardPrune, note: "Правила Docker останутся"},
		{name: "виртуальные машины", vm: true, want: OpForwardPrune, note: "Правила виртуальных машин останутся"},
		{name: "оба", docker: true, vm: true, want: OpForwardPrune, note: "Правила Docker и виртуальных машин останутся"},
		{name: "отрицательный контроль: никого рядом", want: OpForwardAccept},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := standEnv(t, standUnits)
			env.Docker, env.VM = tc.docker, tc.vm
			env.ForwardSources = []string{"docker", "ufw", "netfilter-persistent"}
			p := Build(env)
			fwd := find(t, p, "legacy.forward")
			if last := fwd.Step3[len(fwd.Step3)-1]; !reflect.DeepEqual(last, Op{Kind: tc.want, Family: "ip", Table: "filter", Chain: "FORWARD"}) {
				t.Errorf("пересылка %+v", last)
			}
			if ufw := find(t, p, "foreign.forward.ufw").Step3; ufw[len(ufw)-1].Kind != tc.want {
				t.Errorf("ufw %+v", ufw)
			}
			if tc.note != "" && !strings.Contains(fwd.Found, tc.note) {
				t.Errorf("текст %q без %q", fwd.Found, tc.note)
			}
			for _, it := range p.Items {
				if it.ID == "foreign.forward.docker" {
					t.Errorf("Docker как источник правил не выключаем")
				}
			}
			for id, want := range map[string]bool{"foreign.docker": tc.docker, "foreign.vm": tc.vm} {
				if !want {
					continue
				}
				it := find(t, p, id)
				if !it.Locked || it.Checked || it.Kind != KindLocked || it.Step1 != nil || it.Step3 != nil || it.Undo != nil {
					t.Errorf("запертый пункт %+v", it)
				}
			}
		})
	}
}

func TestForeignNetplan(t *testing.T) {
	macs := map[string]string{"ens3": "52:54:00:aa:00:03", "ens4": "52:54:00:aa:00:04"}
	yaml := func(body string) string { return "network:\n  version: 2\n" + body }
	tests := []struct {
		name  string
		files map[string]string
		want  []string
		found string

		manual bool

		all []string
	}{
		{name: "файл установщика про карту плана",
			files: map[string]string{"/etc/netplan/00-installer-config.yaml": installerYAML},
			want:  []string{"foreign.netplan.00-installer-config.yaml"}, found: "карту ens3"},
		{name: "файл установщика про другую карту",
			files: map[string]string{"/etc/netplan/00-installer-config.yaml": strings.ReplaceAll(installerYAML, "ens3", "ens9")}},
		{name: "маска имени",
			files: map[string]string{"/etc/netplan/01-all.yaml": yaml("  ethernets:\n    all:\n      match: {name: \"en*\"}\n      dhcp4: true\n")},
			want:  []string{"foreign.netplan.01-all.yaml"}, found: "карты ens3, ens4"},

		{name: "маска захватывает и карту вне плана",
			files: map[string]string{"/etc/netplan/01-all.yaml": yaml("  ethernets:\n    all:\n      match: {name: \"en*\"}\n      dhcp4: true\n")},
			want:  []string{"foreign.netplan.01-all.yaml"}, found: "описано all", manual: true,
			all: []string{"ens3", "ens4", "ens5"}},
		{name: "маска на машине без лишних карт",
			files: map[string]string{"/etc/netplan/01-all.yaml": yaml("  ethernets:\n    all:\n      match: {name: \"en*\"}\n      dhcp4: true\n")},
			want:  []string{"foreign.netplan.01-all.yaml"}, found: "карты ens3, ens4",
			all: []string{"ens3", "ens4", "lo"}},
		{name: "маска с вопросом не совпала",
			files: map[string]string{"/etc/netplan/01-eth.yaml": yaml("  ethernets:\n    e:\n      match: {name: \"eth?\"}\n")}},
		{name: "MAC карты плана",
			files: map[string]string{"/etc/netplan/50-cloud-init.yaml": yaml("  ethernets:\n    lan:\n      match: {macaddress: \"52:54:00:AA:00:04\"}\n      set-name: lan\n")},
			want:  []string{"foreign.netplan.50-cloud-init.yaml"}, found: "карту ens4"},
		{name: "MAC чужой карты",
			files: map[string]string{"/etc/netplan/50-cloud-init.yaml": yaml("  ethernets:\n    lan:\n      match: {macaddress: \"52:54:00:aa:00:99\"}\n")}},
		{name: "имя и MAC сразу: MAC не тот",
			files: map[string]string{"/etc/netplan/50-x.yaml": yaml("  ethernets:\n    x:\n      match: {name: ens3, macaddress: \"52:54:00:aa:00:04\"}\n")}},
		{name: "мост забирает карту и пропадёт сам",
			files: map[string]string{"/etc/netplan/10-br.yaml": yaml("  bridges:\n    br0:\n      interfaces: [ens4]\n")},
			want:  []string{"foreign.netplan.10-br.yaml"}, found: "описано br0", manual: true},
		{name: "VLAN поверх карты пропадёт сам",
			files: map[string]string{"/etc/netplan/10-vlan.yaml": yaml("  vlans:\n    v10:\n      id: 10\n      link: ens3\n")},
			want:  []string{"foreign.netplan.10-vlan.yaml"}, found: "описано v10", manual: true},
		{name: "мост с именем карты плана",
			files: map[string]string{"/etc/netplan/10-br.yaml": yaml("  bridges:\n    ens4:\n      interfaces: [ens9]\n")},
			want:  []string{"foreign.netplan.10-br.yaml"}, found: "карту ens4"},
		{name: "ещё и карта вне плана",
			files: map[string]string{"/etc/netplan/00-installer-config.yaml": yaml("  ethernets:\n    ens3: {dhcp4: true}\n    ens5: {dhcp4: true}\n")},
			want:  []string{"foreign.netplan.00-installer-config.yaml"}, found: "описано ens5", manual: true},
		{name: "файл с точкой, не yaml, наш файл, каталог, битый",
			files: map[string]string{
				"/etc/netplan/.00-installer-config.yaml": installerYAML,
				"/etc/netplan/00-installer-config.yml":   installerYAML,
				"/etc/netplan/" + ownNetplan:             installerYAML,
				"/etc/netplan/backup_2026-10-19_133534/": "",
				"/etc/netplan/02-broken.yaml":            "network: [ens3\n",
			}},
		{name: "значение не того вида не прячет остальное",
			files: map[string]string{"/etc/netplan/03-odd.yaml": yaml("  ethernets:\n    ens3:\n      dhcp4: true\n  bonds:\n    bond0:\n      interfaces: ens9\n")},
			want:  []string{"foreign.netplan.03-odd.yaml"}, found: "описано bond0", manual: true},
		{name: "файл старого скрипта без старого шлюза — чужой",
			files: map[string]string{legacyvpn.ScriptNetplan: scriptNetplanYAML},
			want:  []string{"foreign.netplan.99-vpn-script.yaml"}, found: "описано ens2", manual: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := build(t, tc.files)
			p := Build(Env{Root: root, UnitsKnown: true, Units: unitMap{}.fn(),
				PlanCards: []string{"ens4", "ens3"}, AllCards: tc.all, CardMACs: macs, OwnNetplan: ownNetplan})
			if got := ids(p); !reflect.DeepEqual(got, tc.want) && (len(got) > 0 || len(tc.want) > 0) {
				t.Fatalf("пункты %v, ожидали %v", got, tc.want)
			}
			for _, it := range p.Items {
				path := "/etc/netplan/" + strings.TrimPrefix(it.ID, "foreign.netplan.")
				if !reflect.DeepEqual(it.Step1, []Op{{Kind: OpAside, Path: path}}) || !reflect.DeepEqual(it.Step3, []Op{backup(path)}) || it.Undo != nil {
					t.Errorf("шаги %+v", it)
				}
				if !strings.Contains(it.Found, tc.found) {
					t.Errorf("текст %q без %q", it.Found, tc.found)
				}
				if it.Checked == tc.manual {
					t.Errorf("отмечен сам: %v, ожидали %v", it.Checked, !tc.manual)
				}
			}
		})
	}
}

func TestForeignServices(t *testing.T) {
	nftConf := `#!/usr/sbin/nft -f
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`
	tests := []struct {
		name  string
		files map[string]string
		env   Env
		want  map[string][]Op
	}{
		{name: "dnsmasq на карте офиса",
			env:  Env{DHCPUnits: []string{"dnsmasq"}},
			want: map[string][]Op{"foreign.dhcp.dnsmasq": {disable("dnsmasq.service"), mask("dnsmasq.service"), stop("dnsmasq.service")}}},
		{name: "ISC DHCP без старого шлюза",
			env:  Env{DHCPUnits: []string{"isc-dhcp-server.service"}},
			want: map[string][]Op{"foreign.dhcp.isc-dhcp-server": {disable("isc-dhcp-server.service"), mask("isc-dhcp-server.service"), stop("isc-dhcp-server.service")}}},
		{name: "своя служба раздачи в /etc",
			files: map[string]string{"/etc/systemd/system/mydhcp.service": "[Service]\nExecStart=/opt/dhcp\n"},
			env:   Env{DHCPUnits: []string{"mydhcp"}},
			want:  map[string][]Op{"foreign.dhcp.mydhcp": {disable("mydhcp.service"), stop("mydhcp.service"), backup("/etc/systemd/system/mydhcp.service"), reload}}},
		{name: "наш Kea не чужой",
			env: Env{DHCPUnits: []string{"kea-dhcp4-server"}}},
		{name: "раздача NetworkManager только показывается",
			env:  Env{DHCPUnits: []string{"NetworkManager"}},
			want: map[string][]Op{"foreign.dhcp.NetworkManager": nil}},
		{name: "firewalld выключается и останавливается после маски",
			env:  Env{ForwardSources: []string{"firewalld"}},
			want: map[string][]Op{"foreign.forward.firewalld": {disable("firewalld.service"), mask("firewalld.service"), stop("firewalld.service")}}},
		{name: "ufw",
			env: Env{ForwardSources: []string{"ufw"}},
			want: map[string][]Op{"foreign.forward.ufw": {disable("ufw.service"),
				{Kind: OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"}}}},
		{name: "nftables со своим конфигом",
			files: map[string]string{"/etc/nftables.conf": nftConf},
			env:   Env{ForwardSources: []string{"nftables"}},
			want: map[string][]Op{"foreign.forward.nftables": {disable("nftables.service"),
				{Kind: OpForwardPolicy, Family: "inet", Table: "filter", Chain: "forward"}}}},
		{name: "nftables без конфига: цепочки ищет агент",
			env:  Env{ForwardSources: []string{"nftables"}},
			want: map[string][]Op{"foreign.forward.nftables": {disable("nftables.service"), {Kind: OpForwardPolicy}}}},
		{name: "чужое восстановление правил iptables",
			files: map[string]string{legacyvpn.RulesV4: rulesDirect, legacyvpn.RulesV6: rulesV6Open},
			env:   Env{ForwardSources: []string{"netfilter-persistent"}},
			want: map[string][]Op{"foreign.forward.netfilter-persistent": {disable("netfilter-persistent.service"), mask("netfilter-persistent.service"),
				backup(legacyvpn.RulesV4), backup(legacyvpn.RulesV6),
				{Kind: OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"}}}},
		{name: "IPv6 тоже запрещал пересылку",
			files: map[string]string{legacyvpn.RulesV6: rulesV6Drop},
			env:   Env{ForwardSources: []string{"netfilter-persistent"}},
			want: map[string][]Op{"foreign.forward.netfilter-persistent": {disable("netfilter-persistent.service"), mask("netfilter-persistent.service"),
				backup(legacyvpn.RulesV6),
				{Kind: OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"},
				{Kind: OpForwardAccept, Family: "ip6", Table: "filter", Chain: "FORWARD"}}}},
		{name: "Docker как источник не трогаем",
			env: Env{ForwardSources: []string{"docker"}}},
		{name: "пересылка в /etc/sysctl.d",
			files: map[string]string{"/etc/sysctl.d/99-forward.conf": "# сеть\nnet/ipv4/ip_forward = 1\n-net.ipv4.conf.all.forwarding=1\nvm.swappiness=10\n"},
			env:   Env{ForwardBootFiles: []string{"/etc/sysctl.d/99-forward.conf"}},
			want: map[string][]Op{"foreign.sysctl.99-forward.conf": {{Kind: OpCommentKeys, Path: "/etc/sysctl.d/99-forward.conf",
				Keys: []string{"net.ipv4.conf.all.forwarding", "net.ipv4.ip_forward"}}}}},
		{name: "файл пакета вне /etc не правим",
			files: map[string]string{"/usr/lib/sysctl.d/50-x.conf": "net.ipv4.ip_forward=1\n"},
			env:   Env{ForwardBootFiles: []string{"/usr/lib/sysctl.d/50-x.conf"}}},
		{name: "путь пробы без косой черты в начале",
			files: map[string]string{"/etc/sysctl.d/99-forward.conf": "net.ipv4.ip_forward=1\n"},
			env:   Env{ForwardBootFiles: []string{"etc/sysctl.d/99-forward.conf"}},
			want: map[string][]Op{"foreign.sysctl.99-forward.conf": {{Kind: OpCommentKeys, Path: "/etc/sysctl.d/99-forward.conf",
				Keys: []string{"net.ipv4.ip_forward"}}}}},
		{name: "имя юнита с косой чертой отброшено",
			env: Env{DHCPUnits: []string{"../../../etc/passwd", "a b"}, ForwardSources: []string{"x/y"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			env.Root, env.UnitsKnown, env.Units = build(t, tc.files), true, unitMap{}.fn()
			p := Build(env)
			got := map[string][]Op{}
			for _, it := range p.Items {
				got[it.ID] = it.Step3
				if it.Locked != (it.Kind == KindLocked) || it.Checked == it.Locked {
					t.Errorf("флажки %+v", it)
				}

				policyOnly := slices.ContainsFunc(it.Step3, func(o Op) bool { return o.Kind == OpForwardPolicy })
				if it.Kind == KindFirewall && policyOnly != strings.Contains(it.Found, "после перезагрузки") {
					t.Errorf("%s: текст %q не говорит, что останется до перезагрузки", it.ID, it.Found)
				}
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("\nполучено %+v\nожидали  %+v", got, tc.want)
			}
		})
	}
}

func TestTextsForPeople(t *testing.T) {
	env := standEnv(t, standUnits)
	env.Docker, env.VM = true, true
	plans := []Plan{Build(env)}
	root := build(t, map[string]string{
		"/etc/netplan/00-installer-config.yaml": installerYAML,
		"/etc/sysctl.d/99-forward.conf":         "net.ipv4.ip_forward=1\n",
		"/etc/nftables.conf":                    "table inet filter {\n chain forward {\n  type filter hook forward priority 0; policy drop;\n }\n}\n",
	})
	plans = append(plans, Build(Env{Root: root, UnitsKnown: true, Units: unitMap{}.fn(),
		PlanCards: []string{"ens3"}, DHCPUnits: []string{"dnsmasq", "mydhcp", "NetworkManager"},
		ForwardSources:   []string{"firewalld", "nftables", "ufw", "netfilter-persistent", "other"},
		ForwardBootFiles: []string{"/etc/sysctl.d/99-forward.conf"}}))
	for _, p := range plans {
		for _, it := range p.Items {
			for _, s := range []string{it.Title, it.Found} {
				if s == "" {
					t.Errorf("%s: пустой текст", it.ID)
				}
				for _, bad := range []string{"/", ".service", ".yaml", ".conf", "@", "_", "mydhcp", "netfilter", "dsl-provider", "  "} {
					if strings.Contains(s, bad) {
						t.Errorf("%s: %q в тексте %q", it.ID, bad, s)
					}
				}
			}
		}
	}
}

func TestDigest(t *testing.T) {
	env := standEnv(t, standUnits)
	env.HomeScripts = []string{homeScript, "/root/vpn.sh"}
	env.DHCPUnits = []string{"isc-dhcp-server", "dnsmasq"}
	env.ForwardSources = []string{"netfilter-persistent", "firewalld"}
	env.PlanCards = []string{"ens2", "ens3"}
	base := Build(env)
	if base.Digest != Build(env).Digest || base.Digest != Digest(base.Items) || len(base.Digest) != 64 {
		t.Fatalf("отпечаток нестабилен: %s", base.Digest)
	}

	shuffled := env
	shuffled.HomeScripts = []string{"/root/vpn.sh", homeScript, homeScript}
	shuffled.DHCPUnits = []string{"dnsmasq.service", "isc-dhcp-server"}
	shuffled.ForwardSources = []string{"firewalld", "netfilter-persistent"}
	shuffled.PlanCards = []string{"ens3", "ens2"}
	if Build(shuffled).Digest != base.Digest {
		t.Error("перестановка списков обстановки сменила отпечаток")
	}

	flapping := env
	flapping.Units = standUnits.with("telegram_bot.service", etcOn).with("openvpn@client1.service", flaps).fn()
	fp := Build(flapping)
	if fp.Digest != base.Digest {
		t.Error("состояние «работает сейчас» сменило отпечаток")
	}
	if reflect.DeepEqual(find(t, fp, "legacy.tunnel").Undo, find(t, base, "legacy.tunnel").Undo) {
		t.Error("отрицательный контроль: откат должен был поменяться")
	}

	items := slices.Clone(base.Items)
	for i := range items {
		items[i].Title, items[i].Found, items[i].Support = "другое", "другое", nil
	}
	if Digest(items) != base.Digest {
		t.Error("тексты вошли в отпечаток")
	}

	more := env
	more.HomeScripts = append(slices.Clone(env.HomeScripts), homeOf("second"))
	if Build(more).Digest == base.Digest {
		t.Error("новый путь не сменил отпечаток")
	}
	more = env
	more.DHCPUnits = append(slices.Clone(env.DHCPUnits), "udhcpd")
	if Build(more).Digest == base.Digest {
		t.Error("новый пункт не сменил отпечаток")
	}
	more = env
	more.Docker = true
	if Build(more).Digest == base.Digest {
		t.Error("запертый пункт и смена шага не сменили отпечаток")
	}
}

func TestSelect(t *testing.T) {
	env := standEnv(t, standUnits)
	env.Docker = true
	p := Build(env)
	tests := []struct {
		name string
		ids  []string
		want []string
		err  string
	}{
		{name: "пересечение в порядке плана", ids: []string{"legacy.script", "legacy.dhcp", "legacy.dhcp"}, want: []string{"legacy.dhcp", "legacy.script"}},
		{name: "пусто", ids: nil},
		{name: "незнакомый", ids: []string{"legacy.dhcp", "legacy.nothing"}, err: "legacy.nothing"},
		{name: "запертый", ids: []string{"foreign.docker"}, err: "заперт"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Select(tc.ids)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("ошибка %v, ожидали с %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if g := ids(got); !reflect.DeepEqual(g, tc.want) && (len(g) > 0 || len(tc.want) > 0) {
				t.Fatalf("пункты %v, ожидали %v", g, tc.want)
			}
			if got.Digest != p.Digest {
				t.Error("выбор сменил отпечаток плана")
			}
		})
	}
}

func TestNftForwardChains(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want []chainRef
	}{
		{name: "блоки", conf: "table inet filter {\n chain forward { # пересылка\n  type filter hook forward priority 0; policy drop;\n }\n chain input {\n  type filter hook input priority 0;\n }\n}\n",
			want: []chainRef{{"inet", "filter", "forward"}}},
		{name: "таблица без семейства", conf: "table fw {\n chain fwd {\n  type filter hook forward priority 0; policy drop;\n }\n}\n",
			want: []chainRef{{"ip", "fw", "fwd"}}},
		{name: "команды add", conf: "add table ip6 t\nadd chain ip6 t f { type filter hook forward priority 0 ; policy drop ; }\n",
			want: []chainRef{{"ip6", "t", "f"}}},
		{name: "flush без блока и комментарий", conf: "flush table inet filter\n# chain x { type filter hook forward priority 0; }\n"},
		{name: "без хука forward", conf: "table inet filter {\n chain input { type filter hook input priority 0; }\n}\n"},
		{name: "мост и прочие семейства не маршрутизация",
			conf: "table bridge filter {\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n" +
				"table netdev n {\n chain f { type filter hook ingress device ens3 priority 0; }\n}\n" +
				"table inet filter {\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n",
			want: []chainRef{{"inet", "filter", "forward"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nftForwardChains([]byte(tc.conf)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("получено %+v, ожидали %+v", got, tc.want)
			}
		})
	}
}

func TestUnitsCoverQueries(t *testing.T) {
	envs := map[string]Env{}
	stand := standEnv(t, standUnits)
	stand.Docker = true
	stand.ForwardSources = []string{"netfilter-persistent", "firewalld", "nftables", "ufw", "other", "docker"}
	stand.DHCPUnits = []string{"isc-dhcp-server", "dnsmasq", "mydhcp", "NetworkManager"}
	envs["фикстура"] = stand
	envs["без старого шлюза"] = Env{Root: build(t, nil), UnitsKnown: true,
		DHCPUnits: []string{"udhcpd"}, ForwardSources: []string{"nftables", "netfilter-persistent"}}
	for name, env := range envs {
		t.Run(name, func(t *testing.T) {
			asked := map[string]bool{}
			units := env.Units
			env.Units = func(u string) UnitState {
				asked[u] = true
				if units == nil {
					return UnitState{}
				}
				return units(u)
			}
			Build(env)
			if len(asked) == 0 {
				t.Fatal("отрицательный контроль: модель ничего не спросила")
			}
			list := Units(append(slices.Clone(env.DHCPUnits), env.ForwardSources...)...)
			for u := range asked {
				if !slices.Contains(list, u) {
					t.Errorf("модель спросила %s, а в перечне его нет", u)
				}
			}
		})
	}
	all := Units()
	for _, u := range []string{"cron.service", "openvpn.service", "update_metrics.service", "network_load.service",
		"home_metrics_daemon.service", "netfilter-persistent.service", "firewalld.service", "nftables.service",
		"ufw.service", "openvpn@client1.service", "wg-quick@tun0.service", "shellinabox.service", "apache2.service"} {
		if !slices.Contains(all, u) {
			t.Errorf("%s нет в перечне", u)
		}
	}
	for _, u := range legacyvpn.Units() {
		if !slices.Contains(all, u) {
			t.Errorf("%s из описи нет в перечне", u)
		}
	}
	if got := Units("dnsmasq", "bad/name"); !slices.Contains(got, "dnsmasq.service") || slices.ContainsFunc(got, func(u string) bool { return strings.Contains(u, "/") }) {
		t.Errorf("юниты обстановки %v", got)
	}
}

func TestNormalize(t *testing.T) {
	env := normalize(Env{Root: "/",
		ForwardBootFiles: []string{"etc/sysctl.conf", "/etc/sysctl.d/../sysctl.conf", "etc/sysctl.d/99-x.conf"},
		HomeScripts: []string{"/root/vpn.sh", homeScript[1:], homeOf("a/../b"),
			"/etc/passwd", "relative/vpn.sh", "/home/" + "x/../../etc/shadow", homeOf("a/b"), "/home/" + "vpn.sh", "/root/sub/vpn.sh"},
		DHCPUnits:      []string{"dnsmasq", "x@y.service", "a/b", "a b", "-.mount", ".service", "кириллица"},
		ForwardSources: []string{"ufw.service", "../ufw"},
	})
	tests := []struct {
		name      string
		got, want []string
	}{
		{"файлы пересылки от корня", env.ForwardBootFiles, []string{"/etc/sysctl.conf", "/etc/sysctl.d/99-x.conf"}},
		{"сценарии в домашних каталогах", env.HomeScripts, []string{homeOf("b"), homeScript, "/root/vpn.sh"}},
		{"юниты раздачи", env.DHCPUnits, []string{"-.mount", "dnsmasq.service", "x@y.service"}},
		{"источники правил", env.ForwardSources, []string{"ufw.service"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Fatalf("получено %q, ожидали %q", tc.got, tc.want)
			}
		})
	}

	stand := standEnv(t, standUnits)
	stand.HomeScripts = []string{"/etc/passwd", "relative/vpn.sh", "/home/" + "x/../../etc/shadow", homeScript[1:]}
	if got := find(t, Build(stand), "legacy.script").Step3; !reflect.DeepEqual(got, []Op{{Kind: OpStub, Path: homeScript}}) {
		t.Errorf("заглушки %+v", got)
	}
	stand.HomeScripts = []string{"/etc/passwd"}
	if slices.Contains(ids(Build(stand)), "legacy.script") {
		t.Error("пункт сценария без годного пути")
	}
}

func TestTunnelDirs(t *testing.T) {
	ovpn := Op{Kind: OpChownRoot, Path: legacyvpn.OpenVPNDir}
	wg := Op{Kind: OpChownRoot, Path: legacyvpn.WireGuardDir, Mode: 0o700}
	tests := []struct {
		name     string
		files    map[string]string
		want     []Op
		notWants []Op
	}{
		{name: "OpenVPN", files: map[string]string{legacyvpn.OpenVPNConf: "client\n"}, want: []Op{ovpn}, notWants: []Op{wg}},
		{name: "WireGuard", files: map[string]string{legacyvpn.WireGuardConf: "[Interface]\n"}, want: []Op{wg}, notWants: []Op{ovpn}},
		{name: "оба каталога", files: map[string]string{legacyvpn.OpenVPNConf: "client\n", legacyvpn.WireGuardDir + "/": ""}, want: []Op{ovpn, wg}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := legacyEnv(build(t, with(common, tc.files)), standUnits)
			env.LegacyGateway = true
			tun := find(t, Build(env), "legacy.tunnel").Step3
			for _, op := range tc.want {
				if !hasOp(tun, op) {
					t.Errorf("нет %+v в %+v", op, tun)
				}
			}
			for _, op := range tc.notWants {
				if hasOp(tun, op) {
					t.Errorf("каталога нет, а операция есть: %+v", op)
				}
			}
		})
	}
}

func TestMasked(t *testing.T) {
	masked := UnitState{Masked: true}
	tests := []struct {
		name   string
		units  unitMap
		files  map[string]string
		dhcp   []string
		absent string
		ops    map[string][]Op
	}{
		{name: "терминал замаскирован", units: standUnits.with("shellinabox.service", masked), absent: "legacy.terminal"},
		{name: "восстановление правил замаскировано и ещё active",
			units: standUnits.with("netfilter-persistent.service", UnitState{Masked: true, Active: true}),
			files: map[string]string{legacyvpn.RulesV4: ""}, absent: "legacy.forward"},
		{name: "чужая раздача замаскирована, но держит порт",
			units: unitMap{"isc-dhcp-server.service": {Masked: true, Active: true, FileInEtc: true}},
			dhcp:  []string{"isc-dhcp-server"},
			ops: map[string][]Op{"foreign.dhcp.isc-dhcp-server": {disable("isc-dhcp-server.service"),
				mask("isc-dhcp-server.service"), stop("isc-dhcp-server.service")}}},
		{name: "отрицательный контроль: не замаскирована",
			units: unitMap{"isc-dhcp-server.service": {Enabled: true, Active: true, FileInEtc: true}},
			dhcp:  []string{"isc-dhcp-server"},
			ops: map[string][]Op{"foreign.dhcp.isc-dhcp-server": {disable("isc-dhcp-server.service"),
				stop("isc-dhcp-server.service"), backup("/etc/systemd/system/isc-dhcp-server.service"), reload}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var env Env
			if tc.ops == nil {
				root := build(t, with(common, vpnMode))
				for p := range tc.files {
					if err := os.Remove(filepath.Join(root, p)); err != nil {
						t.Fatal(err)
					}
				}
				env = legacyEnv(root, tc.units)
			} else {
				env = Env{Root: build(t, nil), UnitsKnown: true, Units: tc.units.fn(), DHCPUnits: tc.dhcp}
			}
			p := Build(env)
			if tc.absent != "" && slices.Contains(ids(p), tc.absent) {
				t.Errorf("%s есть, хотя делать нечего", tc.absent)
			}
			for id, want := range tc.ops {
				if got := find(t, p, id).Step3; !reflect.DeepEqual(got, want) {
					t.Errorf("\nполучено %+v\nожидали  %+v", got, want)
				}
			}
		})
	}

	p := Build(standEnv(t, standUnits))
	for _, id := range []string{"legacy.terminal", "legacy.forward"} {
		find(t, p, id)
	}
}

func TestPackageUnitMask(t *testing.T) {
	inEtc := UnitState{Enabled: true, Active: true, FileInEtc: true}
	isc := "isc-dhcp-server.service"
	tests := []struct {
		name  string
		files map[string]string
		unit  string
		want  []Op
	}{
		{name: "юнит пакета в /lib", files: map[string]string{"/lib/systemd/system/" + isc: "[Service]\n"}, unit: isc,
			want: []Op{disable(isc), stop(isc), backup("/etc/systemd/system/" + isc), reload, mask(isc)}},
		{name: "юнит пакета в /usr/lib", files: map[string]string{"/usr/lib/systemd/system/" + isc: "[Service]\n"}, unit: isc,
			want: []Op{disable(isc), stop(isc), backup("/etc/systemd/system/" + isc), reload, mask(isc)}},
		{name: "отрицательный контроль: своя служба без пакета", unit: isc,
			want: []Op{disable(isc), stop(isc), backup("/etc/systemd/system/" + isc), reload}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := Env{Root: build(t, tc.files), UnitsKnown: true, Units: unitMap{tc.unit: inEtc}.fn(), DHCPUnits: []string{tc.unit}}
			if got := find(t, Build(env), "foreign.dhcp.isc-dhcp-server").Step3; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("\nполучено %+v\nожидали  %+v", got, tc.want)
			}
		})
	}

	ovpn := "openvpn@client1.service"
	root := build(t, with(common, vpnMode, map[string]string{"/lib/systemd/system/openvpn@.service": "[Service]\n"}))
	env := legacyEnv(root, standUnits.with(ovpn, inEtc))
	tun := find(t, Build(env), "legacy.tunnel").Step3
	want := []Op{disable(ovpn), stop(ovpn), backup("/etc/systemd/system/" + ovpn),
		disable("openvpn.service"), mask("openvpn.service"), stop("openvpn.service"), reload, mask(ovpn)}
	if !reflect.DeepEqual(tun[:len(want)], want) {
		t.Errorf("\nполучено %+v\nожидали  %+v", tun, want)
	}
}

func TestAutostart(t *testing.T) {
	set := Op{Kind: OpSetKey, Path: legacyvpn.OpenVPNDefault, Key: "AUTOSTART", Value: "none"}
	tests := []struct {
		name, text string
		want       bool
	}{
		{"файл скрипта", openvpnDefault, true},
		{"только закомментировано", "#AUTOSTART=\"all\"\n", true},
		{"уже none", "AUTOSTART=\"none\"\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := legacyEnv(build(t, with(common, vpnMode, map[string]string{legacyvpn.OpenVPNDefault: tc.text})), standUnits)
			tun := find(t, Build(env), "legacy.tunnel").Step3
			if hasOp(tun, set) != tc.want {
				t.Fatalf("ключ задаётся %v, ожидали %v: %+v", !tc.want, tc.want, tun)
			}
			for _, op := range tun {
				if op.Kind == OpCommentKeys {
					t.Errorf("ключ закомментирован, а генератор прочтёт это как «все»: %+v", op)
				}
			}
		})
	}
}
