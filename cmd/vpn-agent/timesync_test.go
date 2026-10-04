package main

import (
	"testing"
	"time"
)

func TestClockTargetUsesLocalTime(t *testing.T) {
	zone := time.FixedZone("MSK", 3*60*60)
	now := time.Date(2026, 9, 5, 15, 43, 0, 0, zone)
	got := clockTarget(now, 90*time.Minute)

	if want := "2026-09-05 17:13:00"; got != want {
		t.Fatalf("получено %q, ожидалось %q — время передано не в местной зоне", got, want)
	}

	if got := clockTarget(now, -43*time.Minute); got != "2026-09-05 15:00:00" {
		t.Fatalf("поправка назад: %q", got)
	}

	for _, bad := range []string{"Z", "+", "T"} {
		if len(got) > 0 && containsRune(got, bad) {
			t.Fatalf("в строке времени лишний символ %q: %s", bad, got)
		}
	}
}

func containsRune(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
