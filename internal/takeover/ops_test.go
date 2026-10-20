package takeover

import (
	"strings"
	"testing"
)

func TestOpValid(t *testing.T) {
	tests := []struct {
		name string
		op   Op
		ok   bool
	}{
		{"остановка", stop("isc-dhcp-server.service"), true},
		{"экземпляр шаблона", mask("openvpn@client1.service"), true},
		{"юнит с косой чертой", stop("../x.service"), false},
		{"юнит без суффикса", disable("dnsmasq"), false},
		{"копия", backup("/etc/iptables/rules.v4"), true},
		{"относительный путь", backup("etc/iptables/rules.v4"), false},
		{"путь с выходом наверх", Op{Kind: OpStub, Path: "/home/" + "x/../../etc/shadow"}, false},
		{"строки без строк", Op{Kind: OpDropLines, Path: "/etc/crontab"}, false},
		{"ключи без ключей", Op{Kind: OpCommentKeys, Path: "/etc/sysctl.conf"}, false},
		{"ключ оболочки", Op{Kind: OpSetKey, Path: "/etc/default/openvpn", Key: "AUTOSTART", Value: "none"}, true},
		{"значение с подстановкой", Op{Kind: OpSetKey, Path: "/etc/default/openvpn", Key: "AUTOSTART", Value: "$(id)"}, false},
		{"ключ не имя", Op{Kind: OpSetKey, Path: "/etc/default/openvpn", Key: "A-B", Value: "x"}, false},
		{"каталог root", Op{Kind: OpChownRoot, Path: "/etc/wireguard", Mode: 0o700}, true},
		{"сброс цепочки", Op{Kind: OpForwardAccept, Family: "ip", Table: "filter", Chain: "FORWARD"}, true},
		{"чистка цепочки моста", Op{Kind: OpForwardPrune, Family: "bridge", Table: "filter", Chain: "forward"}, false},
		{"сброс без цепочки", Op{Kind: OpForwardAccept}, false},
		{"политика всех чужих цепочек", Op{Kind: OpForwardPolicy}, true},
		{"политика наполовину", Op{Kind: OpForwardPolicy, Family: "inet"}, false},
		{"команда из перечня", exec(CmdPoff), true},
		{"команда не из перечня", exec("reboot"), false},
		{"ожидание процесса", waitPPPD(), true},
		{"ожидание по пути", Op{Kind: OpWaitGone, Argv0: "/usr/sbin/pppd"}, false},
		{"незнакомая", Op{Kind: "purge"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.op.Valid(); (err == nil) != tc.ok {
				t.Fatalf("годна %v, ожидали %v: %v", err == nil, tc.ok, err)
			}
		})
	}
}

func TestWaitGoneMatches(t *testing.T) {
	tests := []struct {
		name, cmdline string
		want          bool
	}{
		{"pppd старого скрипта", "/usr/sbin/pppd\x00call\x00dsl-provider\x00", true},
		{"pppd по имени без пути", "pppd\x00call\x00dsl-provider", true},
		{"другой пир с тем же началом", "/usr/sbin/pppd\x00call\x00dsl-provider2\x00", false},
		{"лишний аргумент", "/usr/sbin/pppd\x00call\x00dsl-provider\x00nodetach\x00", false},
		{"оболочка сторожа cron", "/bin/sh\x00-c\x00pgrep -f 'pppd call dsl-provider' > /dev/null || /usr/bin/pon dsl-provider\x00", false},
		{"pgrep сторожа", "pgrep\x00-f\x00pppd call dsl-provider\x00", false},
		{"пусто", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitPPPD().Matches([]byte(tc.cmdline)); got != tc.want {
				t.Fatalf("подходит %v, ожидали %v", got, tc.want)
			}
		})
	}
}

func TestSetShellKey(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"файл пакета после скрипта", openvpnDefault, "#AUTOSTART=\"none\"\nAUTOSTART=\"none\"\n"},
		{"два присваивания и export", "AUTOSTART=all\nexport AUTOSTART='home'\nOPTARGS=\"\"\n",
			"AUTOSTART=\"none\"\nAUTOSTART=\"none\"\nOPTARGS=\"\"\n"},
		{"ключа нет", "# только комментарий\n#AUTOSTART=\"all\"\n", "# только комментарий\n#AUTOSTART=\"all\"\nAUTOSTART=\"none\"\n"},
		{"без перевода строки в конце", "OPTARGS=\"\"", "OPTARGS=\"\"\nAUTOSTART=\"none\"\n"},
		{"похожий ключ не трогаем", "AUTOSTART_X=all\n", "AUTOSTART_X=all\nAUTOSTART=\"none\"\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SetShellKey([]byte(tc.in), "AUTOSTART", "none")
			if string(got) != tc.want {
				t.Fatalf("\nполучено %q\nожидали  %q", got, tc.want)
			}
			if again := SetShellKey(got, "AUTOSTART", "none"); string(again) != string(got) {
				t.Errorf("повтор поменял файл: %q", again)
			}
			if v, ok := shellValue(got, "AUTOSTART"); !ok || v != "none" {
				t.Errorf("значение после правки %q", v)
			}
		})
	}
}

func TestShellValue(t *testing.T) {
	tests := []struct {
		name, data, want string
		found            bool
	}{
		{"последнее присваивание", openvpnDefault, "all", true},
		{"только закомментировано", "#AUTOSTART=\"none\"\n", "", false},
		{"одинарные кавычки", "AUTOSTART='none'\n", "none", true},
		{"пустое значение", "AUTOSTART=\n", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if v, ok := shellValue([]byte(tc.data), "AUTOSTART"); v != tc.want || ok != tc.found {
				t.Fatalf("значение %q (%v), ожидали %q (%v)", v, ok, tc.want, tc.found)
			}
		})
	}
}

func TestKeepInForward(t *testing.T) {
	tests := []struct {
		name          string
		jumps, ifaces []string
		want          bool
	}{
		{"переход в цепочку Docker", []string{"DOCKER-USER"}, nil, true},
		{"изоляция Docker", []string{"DOCKER-ISOLATION-STAGE-1"}, nil, true},
		{"мост Docker", nil, []string{"docker0", "ens2"}, true},
		{"сеть Docker пользователя", nil, []string{"br-0f1e2d3c4b5a"}, true},
		{"переход libvirt", []string{"LIBVIRT_FWX"}, nil, true},
		{"мост libvirt", nil, []string{"virbr0"}, true},
		{"запрет старого скрипта", nil, []string{"ens3", "ens2"}, false},
		{"разрешение в канал", nil, []string{"ens3", "tun0"}, false},
		{"переход в чужую цепочку", []string{"ufw-before-forward"}, nil, false},
		{"имя похоже, но не префикс", []string{"MY_DOCKER"}, []string{"lan-docker"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := KeepInForward(tc.jumps, tc.ifaces); got != tc.want {
				t.Fatalf("остаётся %v, ожидали %v", got, tc.want)
			}
		})
	}
}

func TestSavedForwardBlocked(t *testing.T) {
	tests := []struct {
		name, data string
		want       bool
	}{
		{"политика DROP", rulesDirect, true},
		{"правило REJECT при открытой политике", "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i ens3 -o ens2 -j REJECT --reject-with icmp-net-unreachable\nCOMMIT\n", true},
		{"правило DROP в IPv6", rulesV6Drop, true},
		{"всё открыто", rulesV6Open, false},
		{"запрет не в filter", "*mangle\n:FORWARD DROP [0:0]\n-A FORWARD -j DROP\nCOMMIT\n", false},
		{"пусто", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := savedForwardBlocked([]byte(tc.data)); got != tc.want {
				t.Fatalf("запрет %v, ожидали %v", got, tc.want)
			}
		})
	}
}

func TestBuiltOpsValid(t *testing.T) {
	env := standEnv(t, standUnits)
	env.Docker, env.VM = true, true
	env.ForwardSources = []string{"netfilter-persistent", "firewalld", "nftables", "ufw", "other"}
	env.DHCPUnits = []string{"isc-dhcp-server", "dnsmasq", "NetworkManager"}
	n := 0
	for _, it := range Build(env).Items {
		for _, ops := range [][]Op{it.Step1, it.Step3, it.Undo} {
			for _, op := range ops {
				n++
				if err := op.Valid(); err != nil {
					t.Errorf("%s: %v", it.ID, err)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("отрицательный контроль: план пуст, проверять нечего")
	}
	if err := (Op{Kind: OpExec, Command: strings.ToUpper(CmdPoff)}).Valid(); err == nil {
		t.Error("отрицательный контроль: негодная операция прошла")
	}
}

func TestKeepInForwardDockerBridge(t *testing.T) {
	for _, tc := range []struct {
		ifaces []string
		want   bool
	}{
		{[]string{"br-0a1b2c3d4e5f"}, true},
		{[]string{"docker0"}, true},
		{[]string{"virbr0"}, true},

		{[]string{"br-lan"}, false},
		{[]string{"br-0a1b2c3d4e5"}, false},
		{[]string{"eth0", "ens4"}, false},
	} {
		if got := KeepInForward(nil, tc.ifaces); got != tc.want {
			t.Errorf("%v: %v, ждали %v", tc.ifaces, got, tc.want)
		}
	}
}
