package nftgen

import (
	"strings"
	"testing"
)

func TestTunnelAddressOnlyFromTunnel(t *testing.T) {
	p := blackPlan()
	p.Tunnel.Address = "10.66.66.4"
	guard := chainBody(t, string(p.Generate()), "tunnel_guard")
	for _, want := range []string{
		"type filter hook prerouting priority raw; policy accept;",
		`iifname != "wg-vpn0" ip daddr 10.66.66.4 fib saddr type != local counter drop comment "` + TunnelGuardComment + `"`,
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("в защите адреса канала нет %q:\n%s", want, guard)
		}
	}

	unknown := blackPlan()
	white := blackPlan()
	white.Tunnel = nil
	for name, q := range map[string]FirewallPlan{"адрес неизвестен": unknown, "прямой режим": white} {
		if strings.Contains(string(q.Generate()), "chain tunnel_guard") {
			t.Errorf("%s: цепочка защиты адреса канала без адреса", name)
		}
	}
}

func TestTunnelAddressValidated(t *testing.T) {
	for _, bad := range []string{"10.66.66.4; drop", "не-адрес", "::1"} {
		tun := FirewallTunnel{Iface: "wg-vpn0", Address: bad}
		if err := tun.validateOutput(); err == nil {
			t.Errorf("адрес канала %q принят", bad)
		}
	}
	good := FirewallTunnel{Iface: "wg-vpn0", Address: "10.66.66.4"}
	if err := good.validateOutput(); err != nil {
		t.Fatalf("контроль: годный адрес отвергнут: %v", err)
	}
}
