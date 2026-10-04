package reliability

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
)

var t0 = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func at(h float64) time.Time { return t0.Add(time.Duration(h * float64(time.Hour))) }

const (
	up   = "path_tunnel_up"
	down = "path_tunnel_down"
)

func TestCodesComeFromOwners(t *testing.T) {
	c := CurrentCodes()
	if c.Up != up || c.Down != down {
		t.Fatalf("коды канала: %+v", c)
	}
	for _, code := range []string{CodePanelCrashed, CodeUncleanShutdown} {
		e, ok := securitylog.Lookup(code)
		if !ok || e.Class != securitylog.System || !e.Failure || !e.Break {
			t.Errorf("%s: в каталоге обязан быть системным отказом с разрывом наблюдения: %+v", code, e)
		}
		if !c.Failures[code] || !c.Breaks[code] {
			t.Errorf("%s не попал в наборы подсчёта", code)
		}
	}
}

func TestCountWithRepeats(t *testing.T) {
	ev := []Event{
		{Code: down, At: at(-30)},
		{Code: down, At: at(-2), Last: at(-1.99), Repeats: 14},
		{Code: up, At: at(-1)},
	}
	if n := Count(ev, map[string]bool{down: true}, at(-24), at(0)); n != 15 {
		t.Fatalf("за сутки %d, ожидалось 15", n)
	}
	if n := Count(ev, map[string]bool{down: true}, at(-168), at(0)); n != 16 {
		t.Fatalf("за неделю %d, ожидалось 16", n)
	}
}

func TestLongest(t *testing.T) {
	cases := []struct {
		name string
		s    Stretch
		want time.Duration
		ok   bool
	}{
		{"ничего не наблюдалось", Stretch{From: at(-168), Now: at(0)}, 0, false},
		{"подъём и обрыв", Stretch{Events: []Event{{Code: up, At: at(-10)}, {Code: down, At: at(-4)}},
			From: at(-168), Now: at(0)}, 6 * time.Hour, true},
		{"идущий отрезок продлевается, только если канал жив сейчас", Stretch{Events: []Event{{Code: up, At: at(-10)}},
			From: at(-168), Now: at(0), LiveUp: true}, 10 * time.Hour, true},
		{"без живого подтверждения идущий отрезок не утверждается", Stretch{Events: []Event{{Code: up, At: at(-10)}},
			From: at(-168), Now: at(0)}, 0, false},
		{"отрезок обрезается по началу окна", Stretch{Events: []Event{{Code: up, At: at(-200)}, {Code: down, At: at(-100)}},
			From: at(-168), Now: at(0)}, 68 * time.Hour, true},
		{"разрыв наблюдения обрывает отрезок", Stretch{Events: []Event{{Code: up, At: at(-10)}, {Code: down, At: at(-1)}},
			Breaks: []time.Time{at(-5)}, From: at(-168), Now: at(0)}, 5 * time.Hour, true},
		{"мигание: отрезок начинается с последнего подъёма окна", Stretch{Events: []Event{
			{Code: up, At: at(-10), Last: at(-9.99)}, {Code: down, At: at(-10), Last: at(-9.995)}, {Code: down, At: at(-3)}},
			From: at(-168), Now: at(0)}, time.Duration(6.99 * float64(time.Hour)), true},
		{"окно обрывов тянется дольше подъёмов — канал лежит", Stretch{Events: []Event{
			{Code: up, At: at(-10), Last: at(-9.99)}, {Code: down, At: at(-9.999), Last: at(-9.98)}},
			From: at(-168), Now: at(0), LiveUp: false}, 0, false},
		{"после разрыва событий не было, канал жив — отрезок от разрыва", Stretch{Events: []Event{{Code: up, At: at(-50)}},
			Breaks: []time.Time{at(-20)}, From: at(-168), Now: at(0), LiveUp: true}, 30 * time.Hour, true},
		{"после разрыва был обрыв — от разрыва не продлевается", Stretch{Events: []Event{{Code: up, At: at(-50)}, {Code: down, At: at(-2)}},
			Breaks: []time.Time{at(-20)}, From: at(-168), Now: at(0), LiveUp: true}, 30 * time.Hour, true},
	}
	for _, c := range cases {
		c.s.Up, c.s.Down = up, down
		got, ok := Longest(c.s)
		if ok != c.ok || (ok && (got-c.want).Abs() > time.Second) {
			t.Errorf("%s: %v %v, ожидалось %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestJudge(t *testing.T) {
	clean := &models.Boot{CleanStop: true, BootedAt: at(-50), SeenAt: at(-1)}
	dirty := &models.Boot{CleanStop: false, BootedAt: at(-50), SeenAt: at(-1)}
	cases := []struct {
		name      string
		cur, last *models.Boot
		want      string
	}{
		{"первая установка", nil, nil, ""},
		{"перезапуск после штатной остановки", clean, nil, ""},
		{"панель упала внутри загрузки", dirty, nil, CodePanelCrashed},
		{"загрузка после штатного выключения", nil, clean, ""},
		{"загрузка после пропажи питания", nil, dirty, CodeUncleanShutdown},
	}
	for _, c := range cases {
		if v := Judge(c.cur, c.last); v.Code != c.want || (c.want != "" && v.Details == "") {
			t.Errorf("%s: %+v, ожидалось %q", c.name, v, c.want)
		}
	}
}

func TestCompute(t *testing.T) {
	codes := CurrentCodes()
	boots := []models.Boot{
		{ID: 1, BootedAt: at(-100), FirstStartAt: at(-99), LastStartAt: at(-99), SeenAt: at(-60), CleanStop: false},
		{ID: 2, BootedAt: at(-59), FirstStartAt: at(-58.9), LastStartAt: at(-30), SeenAt: at(0)},
	}
	events := []Event{
		{Code: up, At: at(-98.9)},
		{Code: CodeUncleanShutdown, At: at(-58.9)},
		{Code: up, At: at(-58.8)},
		{Code: down, At: at(-40)},
		{Code: up, At: at(-39)},
		{Code: CodePanelCrashed, At: at(-30)},
		{Code: up, At: at(-29.9)},
		{Code: "vpn_apply_failed", At: at(-3)},
	}
	s := compute(at(0), true, codes, boots, events)
	if !s.Observed.Equal(at(-99)) || s.RebootsWeek != 1 || s.UncleanWeek != 1 {
		t.Fatalf("наблюдение/перезагрузки: %+v", s)
	}
	if s.DropsWeek != 1 || s.DropsDay != 0 || s.FailuresDay != 1 {
		t.Fatalf("обрывы/отказы: %+v", s)
	}

	if !s.LongestOK || (s.Longest-time.Duration(38.9*float64(time.Hour))).Abs() > time.Second {
		t.Fatalf("самый длинный отрезок: %v", s.Longest)
	}
	if empty := compute(at(0), false, codes, nil, nil); !empty.Observed.IsZero() {
		t.Fatal("без журнала запусков наблюдения нет")
	}
}
