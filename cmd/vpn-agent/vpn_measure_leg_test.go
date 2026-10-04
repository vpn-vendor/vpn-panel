package main

import (
	"strings"
	"testing"
)

func TestTunnelLegTarget(t *testing.T) {
	const iface = "ovpn-vpn0"

	if ip, refusal := tunnelLegTarget(tunnelFacts{}, iface); ip != nil || refusal == "" {
		t.Fatalf("без адреса дальнего конца ждали названный отказ, получили ip=%v отказ=%q", ip, refusal)
	}

	for _, bad := range []string{"не адрес", "10.77.77.1 ; id", "::1", "10.77.77.300"} {
		ip, refusal := tunnelLegTarget(tunnelFacts{PeerIPv4: bad}, iface)
		if ip != nil || refusal == "" {
			t.Fatalf("на %q ждали названный отказ, получили ip=%v отказ=%q", bad, ip, refusal)
		}
	}

	_, refusal := tunnelLegTarget(tunnelFacts{}, iface)
	for _, forbidden := range []string{"nil", "error", "tunnel_leg", "ICMP", "TTL"} {
		if strings.Contains(refusal, forbidden) {
			t.Fatalf("в отказе сырой технический текст %q: %s", forbidden, refusal)
		}
	}
}
