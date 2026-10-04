package main

import (
	"path/filepath"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

func testComposer(t *testing.T) *modeComposer {
	t.Helper()
	return &modeComposer{path: filepath.Join(t.TempDir(), "net-facts.json")}
}

func pageFirewall(wan string) nftgen.FirewallPlan {
	return nftgen.FirewallPlan{WANs: []string{wan},
		LANs: []nftgen.FirewallLAN{{Name: "ens4", CIDR: "192.168.11.1/24"}}}
}

var testTunnel = &nftgen.FirewallTunnel{Iface: "ovpn-vpn0", Endpoint: "192.168.100.10",
	EndpointPort: 1194, Mark: 51820}

func TestPageCannotDowngradeProtectedMode(t *testing.T) {
	c := testComposer(t)
	c.SetOverlay(modeOverlay{Tunnel: testTunnel})
	got := c.FirewallWith(pageFirewall("ens3"))
	if !got.Black() {
		t.Fatal("страница понизила защищённый режим до прямого доступа")
	}

	c.SetOverlay(modeOverlay{})
	white := c.FirewallWith(pageFirewall("ens3"))
	if white.Black() {
		t.Fatal("без канала рулсет не может быть защищённым")
	}
}

func TestPageFactsCarryNoTunnel(t *testing.T) {
	c := testComposer(t)
	forged := pageFirewall("ens3")
	forged.Tunnel = &nftgen.FirewallTunnel{Iface: "evil0", Endpoint: "203.0.113.66", EndpointPort: 1}
	c.SetFirewallFacts(forged)
	if got := c.Firewall(nftgen.FirewallPlan{}); got.Black() {
		t.Fatalf("надстройка страницы попала в итог: %+v", got.Tunnel)
	}
}

func TestStaleTunnelPlanLosesToCurrentFacts(t *testing.T) {
	c := testComposer(t)
	c.SetFirewallFacts(pageFirewall("ppp0"))
	c.SetOverlay(modeOverlay{Tunnel: testTunnel})
	stale := pageFirewall("ens3")
	stale.Tunnel = testTunnel
	got := c.Firewall(stale)
	if len(got.WANs) != 1 || got.WANs[0] != "ppp0" {
		t.Fatalf("защита собрана по устаревшему WAN: %v", got.WANs)
	}
	if !got.Black() {
		t.Fatal("надстройка режима потеряна")
	}
}

func TestFallbackBootstrapsFactsOnce(t *testing.T) {
	c := testComposer(t)
	got := c.Firewall(pageFirewall("ens3"))
	if len(got.WANs) != 1 || got.WANs[0] != "ens3" {
		t.Fatalf("запасной план не принят: %v", got.WANs)
	}
	if w := c.FirewallWANs(); len(w) != 1 || w[0] != "ens3" {
		t.Fatalf("запасной план не стал фактами: %v", w)
	}

	if got := c.Firewall(pageFirewall("ens9")); got.WANs[0] != "ens3" {
		t.Fatalf("запасной план перебил факты: %v", got.WANs)
	}
}

func TestFactsSurviveRestart(t *testing.T) {
	c := testComposer(t)
	c.SetFirewallFacts(pageFirewall("ppp0"))
	c.SetDNSFacts(unboundgen.Plan{Segments: []unboundgen.Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}}})
	c.SetQoSFacts(qosgen.Plan{Enabled: true, WAN: "ppp0", DownKbit: 100000, UpKbit: 50000})

	again := &modeComposer{path: c.path}
	again.load()
	if w := again.FirewallWANs(); len(w) != 1 || w[0] != "ppp0" {
		t.Fatalf("факты защиты не пережили перезапуск: %v", w)
	}
	if got := again.QoS(qosgen.Plan{}); got.WAN != "ppp0" || got.DownKbit != 100000 {
		t.Fatalf("факты очереди не пережили перезапуск: %+v", got)
	}
}

func TestResolverBindingComesOnlyFromTunnel(t *testing.T) {
	c := testComposer(t)
	page := unboundgen.Plan{Segments: []unboundgen.Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}}}
	c.SetOverlay(modeOverlay{Tunnel: testTunnel, DNSOut: "10.77.77.2"})
	if got := c.DNSWith(page); got.OutgoingAddress != "10.77.77.2" {
		t.Fatalf("страница отвязала резолвер от канала: %q", got.OutgoingAddress)
	}
	page.OutgoingAddress = "203.0.113.66"
	c.SetDNSFacts(page)
	c.SetOverlay(modeOverlay{})
	if got := c.DNS(unboundgen.Plan{}); got.OutgoingAddress != "" {
		t.Fatalf("привязка страницы попала в итог прямого доступа: %q", got.OutgoingAddress)
	}
}

func TestTunnelQueueOnlyWhenTunnelExists(t *testing.T) {
	c := testComposer(t)
	page := qosgen.Plan{Enabled: true, WAN: "ens3", Tunnel: "stale0"}
	c.SetOverlay(modeOverlay{QoSTunnel: "no-such-iface9"})
	if got := c.QoSWith(page); got.Tunnel != "" {
		t.Fatalf("очередь поставлена на несуществующий интерфейс: %q", got.Tunnel)
	}
	c.SetOverlay(modeOverlay{QoSTunnel: "lo"})
	if got := c.QoSWith(page); got.Tunnel != "lo" {
		t.Fatalf("очередь канала потеряна: %q", got.Tunnel)
	}
}

func TestSameNamesIgnoresOrder(t *testing.T) {
	if !sameNames([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("порядок имён не должен иметь значения")
	}
	if sameNames([]string{"ens3"}, []string{"ppp0"}) {
		t.Fatal("смена WAN не распознана")
	}
	if sameNames([]string{"a", "a"}, []string{"a", "b"}) {
		t.Fatal("разные наборы признаны одинаковыми")
	}
}
