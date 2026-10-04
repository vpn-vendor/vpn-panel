package main

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

func unboundCalls(c *modeComposer, overlay modeOverlay) bool {
	got := make(chan struct{}, 4)
	c.onUnbound = func() { got <- struct{}{} }
	c.SetOverlay(overlay)
	c.DNS(unboundgen.Plan{})
	c.DNSWith(unboundgen.Plan{})
	select {
	case <-got:
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}

func TestComposerAsksToRebindResolver(t *testing.T) {
	c := &modeComposer{path: t.TempDir() + "/facts.json"}
	tunnel := &nftgen.FirewallTunnel{Iface: "ovpn-vpn0"}
	if !unboundCalls(c, modeOverlay{Tunnel: tunnel}) {
		t.Fatal("резолвер собран без привязки к каналу, а сторож не позван")
	}
	if unboundCalls(c, modeOverlay{Tunnel: tunnel, DNSOut: "10.77.77.2"}) {
		t.Fatal("привязка есть, а сторож позван зря")
	}
	if unboundCalls(c, modeOverlay{}) {
		t.Fatal("в прямом режиме привязка не нужна, а сторож позван")
	}
}

func TestStoppedSessionWakesWatchdog(t *testing.T) {
	s := &mgmtSession{stop: make(chan struct{}), done: make(chan struct{}), events: make(chan struct{}, 1)}
	go func() { <-s.stop; close(s.done) }()
	d := &ovpnDriver{sess: s}
	ch := d.events()
	d.stopSession()
	select {
	case <-ch:
	default:
		t.Fatal("остановка сессии не разбудила ждущего на её событиях")
	}
}

func TestKickWatchdogDoesNotBlock(t *testing.T) {
	v := &vpnApplier{watchKick: make(chan struct{}, 1)}
	v.kickWatchdog()
	v.kickWatchdog()
	select {
	case <-v.watchKick:
	default:
		t.Fatal("толчок не дошёл")
	}
}

func TestQueueWaitsForGoneWAN(t *testing.T) {
	present := map[string]bool{"ens3": true}
	has := func(n string) bool { return present[n] }
	for name, c := range map[string]struct {
		plan qosgen.Plan
		wait bool
	}{
		"карта ушла при смене пути": {qosgen.Plan{Enabled: true, WAN: "ppp0"}, true},
		"карта на месте":            {qosgen.Plan{Enabled: true, WAN: "ens3"}, false},
		"очередь выключена":         {qosgen.Plan{Enabled: false, WAN: "ppp0"}, false},
		"карта не задана":           {qosgen.Plan{Enabled: true}, false},
	} {
		if got := queueWaitsForWAN(c.plan, has); got != c.wait {
			t.Errorf("%s: %v, ждали %v", name, got, c.wait)
		}
	}
}
