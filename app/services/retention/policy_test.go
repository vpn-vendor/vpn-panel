package retention

import (
	"errors"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

func TestApprovedNumbers(t *testing.T) {
	checks := []struct {
		name      string
		got, want int
	}{
		{"срок журнала по умолчанию", JournalDaysDefault, 90},
		{"срок журнала, нижняя граница", JournalDaysMin, 30},
		{"срок журнала, верхняя граница", JournalDaysMax, 365},
		{"забывание устройств по умолчанию", ForgetDaysDefault, 30},
		{"потолок обычных событий", OrdinaryCap, 50000},
		{"потолок критичных событий", CriticalCap, 20000},
		{"системные события: гарантия суток", SystemKeepDays, 7},
		{"системные события: гарантия суток при нехватке диска", SystemKeepDaysTight, 1},
		{"журнал запусков, суток", BootsKeepDays, 8},
		{"порция уборки", Batch, 1000},
		{"истёкшие коды, дней", CodesKeepDays, 90},
		{"след мёртвого доверия по умолчанию, дней", TrustKeepDaysDefault, 30},
		{"след мёртвого доверия, нижняя граница", TrustKeepDaysMin, 7},
		{"след мёртвого доверия, верхняя граница", TrustKeepDaysMax, 365},
		{"новых устройств в час", NewDevicesPerHour, 256},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: %d, утверждено %d", c.name, c.got, c.want)
		}
	}
	if SweepEvery != time.Minute || SweepBudget != time.Second || DeviceWriteEvery != time.Minute {
		t.Error("интервалы уборки изменены")
	}
}

func TestValidateAndClamp(t *testing.T) {
	if len(validateTerms(Settings{JournalDays: 90, ForgetDays: 30, TrustDays: 30})) != 0 {
		t.Fatal("значения по умолчанию обязаны проходить")
	}
	for _, st := range []Settings{{29, 30, 30}, {366, 30, 30}, {90, 6, 30}, {90, 366, 30}, {90, 30, 6}, {90, 30, 366}} {
		if len(validateTerms(st)) == 0 {
			t.Errorf("%+v вне границ, но принято", st)
		}
	}
	if clamp(0, 30, 365, 90) != 90 || clamp(5, 30, 365, 90) != 30 || clamp(9999, 30, 365, 90) != 365 || clamp(120, 30, 365, 90) != 120 {
		t.Fatal("прижим к границам нарушен")
	}
}

func TestForgettable(t *testing.T) {
	now := time.Unix(10_000_000, 0)
	cutoff := now.AddDate(0, 0, -30)
	old := cutoff.Add(-time.Hour)
	proposed := now
	cases := []struct {
		name string
		d    models.Device
		want bool
	}{
		{"случайный MAC, давно, без подписи", models.Device{MAC: "da:11:22:33:44:55", LastSeenAt: old}, true},
		{"настоящий MAC", models.Device{MAC: "00:1a:2b:33:44:55", LastSeenAt: old}, false},
		{"подписан администратором", models.Device{MAC: "da:11:22:33:44:55", Label: "Бухгалтерия", LastSeenAt: old}, false},
		{"есть только заметка", models.Device{MAC: "da:11:22:33:44:55", Note: "проверить", LastSeenAt: old}, false},
		{"есть предложение подписи", models.Device{MAC: "da:11:22:33:44:55", ProposedAt: &proposed, LastSeenAt: old}, false},
		{"был в сети недавно", models.Device{MAC: "da:11:22:33:44:55", LastSeenAt: now}, false},
	}
	for _, c := range cases {
		if got := Forgettable(c.d, cutoff); got != c.want {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

func TestRunPartsBudgetAndBatches(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := now
	calls := map[string]int{}
	parts := []sweepPart{
		{"полные порции", func() (int, error) { calls["full"]++; clock = clock.Add(100 * time.Millisecond); return Batch, nil }},
		{"пусто", func() (int, error) { calls["empty"]++; return 0, errNothing }},
	}
	runParts(parts, now.Add(time.Second), func() time.Time { return clock })
	if calls["full"] != 10 {
		t.Fatalf("полная часть вызвана %d раз, бюджет 1 с при 100 мс на порцию = 10", calls["full"])
	}
	if calls["empty"] != 0 {
		t.Fatal("после исчерпания бюджета следующие части не запускаются в этом проходе")
	}

	clock = now
	calls = map[string]int{}
	parts = []sweepPart{
		{"неполная", func() (int, error) { calls["partial"]++; return Batch - 1, nil }},
		{"ошибка", func() (int, error) { calls["err"]++; return 0, errors.New("база занята") }},
		{"следующая", func() (int, error) { calls["next"]++; return 0, errNothing }},
	}
	runParts(parts, now.Add(time.Second), func() time.Time { return clock })
	if calls["partial"] != 1 || calls["err"] != 1 || calls["next"] != 1 {
		t.Fatalf("неполная порция и ошибка обязаны завершать часть, но не проход: %v", calls)
	}
}
