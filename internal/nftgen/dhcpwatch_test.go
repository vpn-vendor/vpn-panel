package nftgen

import (
	"strings"
	"testing"
	"time"
)

func officeWatch() DHCPWatch {
	return DHCPWatch{
		LANs:     []string{"ens5", "ens4"},
		Prefixes: []string{"192.168.77.1/24", "10.0.5.1/23"},

		OwnMACs: []string{"52:54:00:AA:bb:01", "52:54:00:aa:bb:01", "02:00:00:00:00:02"},
	}
}

const officeWatchRule = `iifname { "ens4", "ens5" } udp sport 67 udp dport 68 ether saddr != { 02:00:00:00:00:02, 52:54:00:aa:bb:01 } update @dhcp_seen { ether saddr . ip saddr }`

func TestDHCPWatchCreateGolden(t *testing.T) {
	w := officeWatch()
	if err := w.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	want := `table inet vpn_panel_dhcp
delete table inet vpn_panel_dhcp
table inet vpn_panel_dhcp {
	set dhcp_seen {
		type ether_addr . ipv4_addr
		size 764
		flags dynamic,timeout
		timeout 4d
	}
	set dhcp_window {
		type inet_service
		flags timeout
	}
	chain watch {
		type filter hook prerouting priority raw - 10; policy accept;
		` + officeWatchRule + `
	}
}
add element inet vpn_panel_dhcp dhcp_window { 67 timeout 1d }
`
	if got := w.Create(DHCPFresh, DHCPWindow); got != want {
		t.Fatalf("таблица наблюдения разошлась с эталоном:\n%s", got)
	}
}

func TestDHCPWatchSyncAndRestart(t *testing.T) {
	w := officeWatch()
	sync := "flush chain inet vpn_panel_dhcp watch\nadd rule inet vpn_panel_dhcp watch " + officeWatchRule + "\n"
	if got := w.Sync(); got != sync {
		t.Fatalf("Sync:\n%s", got)
	}
	restart := "flush set inet vpn_panel_dhcp dhcp_seen\nflush set inet vpn_panel_dhcp dhcp_window\n" +
		"add element inet vpn_panel_dhcp dhcp_window { 67 timeout 3600s }\n"
	if got := w.Restart(time.Hour); got != restart {
		t.Fatalf("Restart:\n%s", got)
	}
	for name, s := range map[string]string{"Sync": w.Sync(), "Restart": w.Restart(time.Hour)} {
		if strings.Contains(s, "delete") || strings.Contains(s, "table inet") {
			t.Errorf("%s пересоздаёт таблицу и стирает наблюдения:\n%s", name, s)
		}
	}
}

func TestDHCPWatchWithoutOwnMACs(t *testing.T) {
	w := officeWatch()
	for name, macs := range map[string][]string{"нет": nil, "пусто": {}} {
		w.OwnMACs = macs
		for kind, s := range map[string]string{"Create": w.Create(DHCPFresh, DHCPWindow), "Sync": w.Sync()} {
			if strings.Contains(s, "ether saddr !=") || strings.Contains(s, "{ }") {
				t.Errorf("%s/%s: условие с пустым набором:\n%s", name, kind, s)
			}
			if !strings.Contains(s, `udp sport 67 udp dport 68 update @dhcp_seen { ether saddr . ip saddr }`) {
				t.Errorf("%s/%s: нет правила наблюдения:\n%s", name, kind, s)
			}
		}
	}
	w.OwnMACs = []string{"00:00:5e:00:53:01"}
	if !strings.Contains(w.Sync(), "ether saddr != { 00:00:5e:00:53:01 } update") {
		t.Fatalf("контроль: свой MAC не исключён:\n%s", w.Sync())
	}
}

func TestDHCPWatchValidateRejects(t *testing.T) {
	ok := officeWatch()
	if err := ok.Validate(); err != nil {
		t.Fatalf("контроль: годная таблица отвергнута: %v", err)
	}
	for name, mut := range map[string]func(*DHCPWatch){
		"нет карт":              func(w *DHCPWatch) { w.LANs = nil },
		"имя с командой":        func(w *DHCPWatch) { w.LANs = []string{`ens4" } accept; flush ruleset; {"`} },
		"имя с пробелом":        func(w *DHCPWatch) { w.LANs = []string{"ens 4"} },
		"карта дважды":          func(w *DHCPWatch) { w.LANs = []string{"ens4", "ens4"} },
		"нет подсетей":          func(w *DHCPWatch) { w.Prefixes = nil },
		"подсеть-мусор":         func(w *DHCPWatch) { w.Prefixes = []string{"nope"} },
		"адрес без маски":       func(w *DHCPWatch) { w.Prefixes = []string{"192.168.77.1"} },
		"подсеть IPv6":          func(w *DHCPWatch) { w.Prefixes = []string{"fd00::1/64"} },
		"IPv4 внутри IPv6":      func(w *DHCPWatch) { w.Prefixes = []string{"::ffff:192.168.77.1/120"} },
		"MAC-мусор":             func(w *DHCPWatch) { w.OwnMACs = []string{"nope"} },
		"MAC через дефис":       func(w *DHCPWatch) { w.OwnMACs = []string{"52-54-00-aa-bb-01"} },
		"MAC через точку":       func(w *DHCPWatch) { w.OwnMACs = []string{"5254.00aa.bb01"} },
		"MAC длинный":           func(w *DHCPWatch) { w.OwnMACs = []string{"02:00:00:00:00:00:00:01"} },
		"MAC с командой":        func(w *DHCPWatch) { w.OwnMACs = []string{"02:00:00:00:00:01 } accept"} },
		"MAC без ведущих нулей": func(w *DHCPWatch) { w.OwnMACs = []string{"2:0:0:0:0:1"} },
	} {
		w := officeWatch()
		mut(&w)
		if err := w.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestDHCPWatchSize(t *testing.T) {
	for _, c := range []struct {
		prefixes []string
		want     int
	}{
		{[]string{"192.168.77.1/24"}, 254},
		{[]string{"192.168.77.1/24", "10.0.5.1/24"}, 508},
		{[]string{"192.168.77.1/24", "192.168.77.20/24"}, 254},
		{[]string{"10.0.0.1/8"}, 16777214},
		{[]string{"10.0.0.1/30"}, 2},
		{[]string{"10.0.0.1/31"}, 1},
		{[]string{"10.0.0.1/32"}, 1},
		{nil, 1},
		{[]string{"nope", "fd00::1/64"}, 1},
	} {
		if got := (DHCPWatch{Prefixes: c.prefixes}).Size(); got != c.want {
			t.Errorf("%v: потолок %d, ждали %d", c.prefixes, got, c.want)
		}
	}
}

func TestNftDuration(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{DHCPFresh, "4d"},
		{DHCPWindow, "1d"},
		{time.Hour, "3600s"},
		{36 * time.Hour, "129600s"},
		{90 * time.Second, "90s"},
		{1500 * time.Millisecond, "2s"},
		{time.Millisecond, "1s"},
		{0, "1s"},
		{-time.Hour, "1s"},
	} {
		if got := nftDuration(c.d); got != c.want {
			t.Errorf("%v: %q, ждали %q", c.d, got, c.want)
		}
	}
}
