package vpn

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

func TestKillSwitchIsStrictByDefault(t *testing.T) {
	for _, raw := range []string{"", "strict", "STRICT", "Direct", "direct ", "выпускать", "0", "true", "null"} {
		got := NormalizeSettings(Settings{OnFailure: raw}).OnFailure
		if got != FailStrict {
			t.Errorf("значение %q дало %q — ожидался строгий запрет", raw, got)
		}
	}

	if got := NormalizeSettings(Settings{OnFailure: FailDirect}).OnFailure; got != FailDirect {
		t.Fatalf("осознанный выбор администратора обязан сохраняться, получено %q", got)
	}
}

func TestModeDefaultsToDirectInternet(t *testing.T) {
	for _, raw := range []string{"", "white", "чёрный", "BLACK", "1"} {
		if got := NormalizeSettings(Settings{Mode: raw}).Mode; got != ModeWhite {
			t.Errorf("режим %q дал %q — ожидался прямой доступ", raw, got)
		}
	}
	if got := NormalizeSettings(Settings{Mode: ModeBlack}).Mode; got != ModeBlack {
		t.Fatal("выбранный защищённый режим обязан сохраняться")
	}
}

func TestDNSDefaultsToOurResolver(t *testing.T) {
	for _, raw := range []string{"", "ours", "CONFIG", "файл"} {
		if got := NormalizeSettings(Settings{DNSChoice: raw}).DNSChoice; got != DNSOurs {
			t.Errorf("выбор %q дал %q — ожидался наш резолвер", raw, got)
		}
	}
	if got := NormalizeSettings(Settings{DNSChoice: DNSConfig}).DNSChoice; got != DNSConfig {
		t.Fatal("осознанный выбор администратора обязан сохраняться")
	}
}

func TestMTUOutOfRangeFallsBackToAuto(t *testing.T) {
	for _, mtu := range []int{-1, 1, 576, wggen.MinMTU - 1, wggen.MaxMTU + 1, 9000} {
		if got := NormalizeSettings(Settings{MTU: mtu}).MTU; got != 0 {
			t.Errorf("размер %d дал %d — ожидался авторасчёт (0)", mtu, got)
		}
	}
	for _, mtu := range []int{wggen.MinMTU, 1412, wggen.MaxMTU} {
		if got := NormalizeSettings(Settings{MTU: mtu}).MTU; got != mtu {
			t.Errorf("допустимый размер %d не сохранился: %d", mtu, got)
		}
	}
}
