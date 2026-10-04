package nftgen

import (
	"strings"
	"testing"
)

func TestLockdownGolden(t *testing.T) {
	p := FirewallPlan{
		WANs: []string{"ppp0", "ens3"},
		LANs: []FirewallLAN{{Name: "ens5", CIDR: "10.0.5.1/24"}, {Name: "ens4", CIDR: "192.168.77.1/24"}},
	}
	want := `table inet vpn_panel
delete table inet vpn_panel
table inet vpn_panel {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname { "ens4", "ens5" } accept
		iifname { "ens3", "ppp0" } udp sport 67 udp dport 68 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		oifname { "ens4", "ens5" } accept
		oifname { "ens3", "ppp0" } udp sport 68 udp dport 67 accept
	}
}
`
	if got := string(p.Lockdown()); got != want {
		t.Fatalf("аварийный набор разошёлся с эталоном:\n%s", got)
	}
}

func TestLockdownHasNoAddressBoundary(t *testing.T) {
	p := FirewallPlan{
		WANs: []string{"ens3.100"},
		LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.11.1/24"}},
	}
	out := string(p.Lockdown())
	for _, bad := range []string{"224.0.0.0", "192.168.0.0", "10.0.0.0", "172.16.0.0", "169.254", "255.255.255.255", "masquerade", "saddr", "daddr", "ct state"} {
		if strings.Contains(out, bad) {
			t.Errorf("аварийный набор содержит границу по адресу или NAT: %q", bad)
		}
	}
	if strings.Count(out, "policy drop") != 3 {
		t.Errorf("все три цепочки обязаны закрываться политикой drop:\n%s", out)
	}
	wan := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"ens3.100"`) {
			wan++
			if !strings.Contains(line, "udp sport 6") || !strings.Contains(line, "udp dport 6") {
				t.Errorf("с WAN разрешено что-то кроме DHCP-клиента: %s", line)
			}
		}
	}
	if wan != 2 {
		t.Errorf("на WAN ожидались ровно два правила DHCP-клиента, найдено %d", wan)
	}
}

func TestLockdownWithoutLANIsAbsent(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}}
	if out := p.Lockdown(); out != nil {
		t.Fatalf("без LAN аварийного файла быть не должно — войти некуда:\n%s", out)
	}
}

func TestLockdownWithoutWANKeepsOfficeOnly(t *testing.T) {
	p := FirewallPlan{LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.11.1/24"}}}
	out := string(p.Lockdown())
	if strings.Contains(out, "udp sport") {
		t.Errorf("без WAN правил DHCP-клиента быть не должно:\n%s", out)
	}
	if !strings.Contains(out, `iifname { "ens4" } accept`) {
		t.Errorf("сеть офиса обязана остаться открытой:\n%s", out)
	}
}
