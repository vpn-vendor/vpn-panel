package diag

import (
	"strings"
	"testing"
	"time"
)

func newFullCheckTest(now time.Time) (*FullCheck, mapWindowStore, *[]string) {
	st := mapWindowStore{}
	var events []string
	f := &FullCheck{store: st, now: func() time.Time { return now },
		audit: func(e, ip, d string) { events = append(events, e+": "+d) }, max: func() int { return 24 }}
	return f, st, &events
}

func TestFullCheckConsentExpiryAndStop(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f, st, events := newFullCheckTest(now)
	if f.State().Active {
		t.Fatal("режим по умолчанию обязан быть выключен")
	}
	if _, err := f.Start(time.Hour, false, "10.0.0.1"); err == nil {
		t.Fatal("старт без согласия принят")
	}
	if _, err := f.Start(25*time.Hour, true, "10.0.0.1"); err == nil {
		t.Fatal("срок сверх предела принят")
	}
	s, err := f.Start(time.Hour, true, "10.0.0.1")
	if err != nil || !s.Active || !s.Until.Equal(now.Add(time.Hour)) || st[SettingFullCheckUntil] == "" {
		t.Fatalf("старт: %+v %v", s, err)
	}
	if len(*events) != 1 || !strings.Contains((*events)[0], "качество звонков не гарантируется") {
		t.Fatalf("журнал старта без обязательного текста: %v", *events)
	}
	f.now = func() time.Time { return now.Add(time.Hour + time.Second) }
	if f.State().Active {
		t.Fatal("истёкший режим активен")
	}
	if len(*events) != 2 || !strings.HasPrefix((*events)[1], "lan_fullcheck_ended") || st[SettingFullCheckUntil] != "" {
		t.Fatalf("конец по сроку не записан: %v", *events)
	}
	if f.State().Active || len(*events) != 2 {
		t.Fatal("повторный опрос истёкшего режима не должен писать событие дважды")
	}
	_, _ = f.Start(time.Hour, true, "10.0.0.1")
	if err := f.Stop("10.0.0.1"); err != nil || f.State().Active || !strings.HasPrefix((*events)[len(*events)-1], "lan_fullcheck_stopped") {
		t.Fatalf("остановка: %v %v", err, *events)
	}
}
