package security

import (
	"strings"
	"testing"
	"time"
)

func TestLeakDelta(t *testing.T) {
	for _, c := range []struct {
		name        string
		prev        int64
		known       bool
		cur         int64
		watched     bool
		delta, next int64
		nextKnown   bool
	}{
		{"прямой режим — сигнализации нет", 5, true, 0, false, 0, 0, false},
		{"первое чтение, чисто", 0, false, 0, true, 0, 0, true},
		{"первое чтение, уже насчитано", 0, false, 3, true, 3, 3, true},
		{"рост", 3, true, 7, true, 4, 7, true},
		{"без изменений", 7, true, 7, true, 0, 7, true},
		{"правила перезаписаны — отсчёт заново", 7, true, 2, true, 2, 2, true},
		{"правила перезаписаны, чисто", 7, true, 0, true, 0, 0, true},
	} {
		d, n, k := leakDelta(c.prev, c.known, c.cur, c.watched)
		if d != c.delta || n != c.next || k != c.nextKnown {
			t.Errorf("%s: (%d %d %v), ждали (%d %d %v)", c.name, d, n, k, c.delta, c.next, c.nextKnown)
		}
	}
}

func TestLeakNoticeLifetime(t *testing.T) {
	raw := "1790409600 3"
	at := time.Unix(1790409600, 0)
	if txt := leakNoticeText(raw, at.Add(time.Hour)); !strings.Contains(txt, "пакетов — 3") {
		t.Fatalf("плашка не показана: %q", txt)
	}
	if txt := leakNoticeText(raw, at.Add(LeakNoticeFor+time.Minute)); txt != "" {
		t.Fatalf("плашка держится дольше срока: %q", txt)
	}
	for _, bad := range []string{"", "мусор", "abc 3"} {
		if txt := leakNoticeText(bad, at); txt != "" {
			t.Errorf("испорченное значение %q дало плашку", bad)
		}
	}
}
