package diag

import (
	"testing"
	"time"
)

type mapWindowStore map[string]string

func (m mapWindowStore) Get(k string) string   { return m[k] }
func (m mapWindowStore) Set(k, v string) error { m[k] = v; return nil }

func newWindowTest(now time.Time) (*Window, mapWindowStore) {
	st := mapWindowStore{}
	w := NewWindow(st)
	w.now = func() time.Time { return now }
	return w, st
}

func TestWindowNumbersFrozen(t *testing.T) {
	if WindowDefault != 2*time.Hour || WindowMaxHours != 24 || WindowMinutes != 1 || WindowMaxHrsHi != 24 {
		t.Fatal("сроки окна изменены (владелец: 2 ч по умолчанию, предел 24 ч)")
	}
}

func TestWindowOpenClampAndExpire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w, st := newWindowTest(now)
	if w.State().Open {
		t.Fatal("по умолчанию окно обязано быть закрыто")
	}
	if _, err := w.Open(25*time.Hour, false); err == nil {
		t.Fatal("окно дольше предела принято")
	}
	if _, err := w.Open(30*time.Second, false); err == nil {
		t.Fatal("окно короче минуты принято")
	}
	s, err := w.Open(WindowDefault, true)
	if err != nil || !s.Open || !s.FullAllowed || !s.Until.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("открытие: %+v %v", s, err)
	}
	if st[SettingWindowUntil] == "" {
		t.Fatal("состояние не записано в хранилище — перезагрузку не переживёт")
	}
	w.now = func() time.Time { return now.Add(2*time.Hour + time.Second) }
	if s := w.State(); s.Open || s.FullAllowed {
		t.Fatalf("истёкшее окно обязано быть закрыто: %+v", s)
	}
}

func TestWindowExtendCloseAndMax(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w, _ := newWindowTest(now)
	if _, err := w.Extend(time.Hour); err == nil {
		t.Fatal("продление закрытого окна принято")
	}
	_, _ = w.Open(time.Hour, false)
	s, err := w.Extend(time.Hour)
	if err != nil || !s.Until.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("продление: %+v %v", s, err)
	}
	if _, err := w.Extend(23 * time.Hour); err == nil {
		t.Fatal("продление сверх предела принято")
	}
	if err := w.store.Set(SettingWindowMaxHours, "1"); err != nil || w.FitOpenTo(1) != nil {
		t.Fatal("новый предел не записан")
	}
	if s := w.State(); !s.Until.Equal(now.Add(time.Hour)) || s.MaxHours != 1 {
		t.Fatalf("снижение предела не укоротило окно: %+v", s)
	}
	if err := w.Close(); err != nil || w.State().Open {
		t.Fatal("закрытие не сработало")
	}
}
