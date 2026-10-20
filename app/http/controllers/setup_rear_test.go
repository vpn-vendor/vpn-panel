package controllers

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

func TestPortAdviceFollowsTariff(t *testing.T) {
	fast := sysinfo.Port{Name: "eno1", SpeedMbit: 1000, SpeedKnown: true}
	slow := sysinfo.Port{Name: "ens4", SpeedMbit: 100, SpeedKnown: true}

	a := portAdvice(fast, slow)
	if len(a.Options) != 2 || a.Options[0].Label != "до 100 Мбит/с" {
		t.Fatalf("варианты тарифа: %+v", a.Options)
	}

	if a.Options[0].Level == ui.Warn || !strings.Contains(a.Options[0].Text, "ens4") || !strings.Contains(a.Options[0].Text, "не обязательно") {
		t.Errorf("при тарифе до 100 Мбит/с перестановка — мягкий совет с оговоркой: %+v", a.Options[0])
	}
	if a.Options[1].Level != ui.OK {
		t.Errorf("при тарифе больше 100 Мбит/с быстрое гнездо провайдеру — верно: %+v", a.Options[1])
	}

	b := portAdvice(slow, fast)
	if b.Options[0].Level != ui.OK || b.Options[1].Level != ui.Warn {
		t.Errorf("медленная карта провайдеру: %+v", b.Options)
	}

	if c := portAdvice(fast, sysinfo.Port{Name: "ens4"}); c.Single == nil || c.Options != nil {
		t.Errorf("без скорости второй карты совет один и честный: %+v", c)
	}
	if d := portAdvice(fast, sysinfo.Port{Name: "eno2", SpeedMbit: 1000, SpeedKnown: true}); d.Single == nil || d.Single.Level != ui.OK {
		t.Errorf("одинаковые карты — подключено правильно: %+v", d)
	}
	if speedText(2500) != "2,5 Гбит/с" || speedText(1000) != "1 Гбит/с" {
		t.Errorf("скорость человеку: %s %s", speedText(2500), speedText(1000))
	}
}

func TestRearBoardPortIsFirstCard(t *testing.T) {
	one := setup.Facts{Cards: []setup.Card{{Name: "eth0", Up: true}}}
	rear, _ := pcRearOf(one, "eth0")
	if len(rear.Ports) != 1 || !rear.Ports[0].Board || rear.Ports[0].Name != "eth0" || !rear.Ports[0].Provider {
		t.Fatalf("одна карта — в гнезде платы с кабелем: %+v", rear.Ports)
	}
	if rear.Missing == nil || rear.Missing.RingY != rearNICYs[0]-3 {
		t.Errorf("свободный слот обведён на месте платы: %+v", rear.Missing)
	}
	for _, y := range []int{rearNICYs[0], rearNICYs[0] + rearSlotStep} {
		found := false
		for _, p := range rear.Plain {
			found = found || p == y
		}
		if !found {
			t.Errorf("в пустом слоте %d должна стоять заглушка", y)
		}
	}
	two := setup.Facts{Cards: []setup.Card{{Name: "ens2", Up: true}, {Name: "ens3"}}}
	rear, _ = pcRearOf(two, "ens2")
	if !rear.Ports[0].Board || rear.Ports[0].Name != "ens2" || rear.Ports[1].Board || rear.Missing != nil {
		t.Errorf("две карты: первая на плате, вторая в слоте: %+v", rear.Ports)
	}
	if rear.Guess == "" {
		t.Error("место угадано — подпись «примерное» нужна")
	}
}
