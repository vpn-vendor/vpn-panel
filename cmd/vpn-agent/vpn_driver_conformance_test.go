package main

import (
	"reflect"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

func TestEveryProtocolHasMatchingDriver(t *testing.T) {
	drivers := newDrivers()
	for _, d := range vpnproto.All() {
		drv, ok := drivers[d.ID]
		if !ok {
			t.Errorf("у протокола %s нет драйвера агента", d.ID)
			continue
		}
		if drv.protocol() != d.ID || drv.iface() != d.Iface {
			t.Errorf("%s: драйвер называет себя %s/%s", d.ID, drv.protocol(), drv.iface())
		}
		for _, tr := range d.Transports {
			if !reflect.DeepEqual(drv.passport(tr), d.Passport(tr)) {
				t.Errorf("%s/%s: паспорт драйвера расходится с описанием", d.ID, tr)
			}
		}
		_, canPause := drv.(pausable)
		if canPause != d.Passport("").CanPause {
			t.Errorf("%s: паспорт говорит «пауза %v», а драйвер умеет её: %v", d.ID, d.Passport("").CanPause, canPause)
		}
	}
	for id := range driverCtors {
		if !vpnproto.Known(id) {
			t.Errorf("драйвер %s есть, а протокола в сборке нет", id)
		}
	}
}

func TestUnknownAndNoProtocolAreRefused(t *testing.T) {
	v := &vpnApplier{drivers: newDrivers()}
	for _, p := range []string{"", "ipsec"} {
		st := vpnState{Plan: vpnPlan{Protocol: p}}
		if _, ok := v.driver(&st).(unknownDriver); !ok {
			t.Errorf("протокол %q получил чужой драйвер", p)
		}
	}
}

func TestStoredPlanProtocol(t *testing.T) {
	if got := storedProtocol(vpnPlan{Slug: "office"}); !vpnproto.Known(got) {
		t.Fatalf("старый план с профилем: %q", got)
	}
	if got := storedProtocol(vpnPlan{}); got != "" {
		t.Fatalf("план без профиля получил протокол %q", got)
	}
}
