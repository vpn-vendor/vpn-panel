package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenBlocked(t *testing.T) {
	l := New(3, 1, time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("ip1") {
			t.Fatalf("attempt %d should pass", i+1)
		}
	}
	if l.Allow("ip1") {
		t.Fatal("4th attempt must be blocked")
	}
	if !l.Allow("ip2") {
		t.Fatal("independent key must not be affected")
	}
}

func TestRefill(t *testing.T) {
	l := New(1, 1000, time.Second)
	if !l.Allow("k") {
		t.Fatal("first must pass")
	}
	if l.Allow("k") {
		t.Fatal("second immediate must be blocked")
	}
	time.Sleep(5 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("after refill must pass")
	}
}

func TestReadyAndCharge(t *testing.T) {
	l := New(2, 1, time.Hour)
	for i := 0; i < 10; i++ {
		if !l.Ready("k") {
			t.Fatal("удачные попытки не тратят ведро")
		}
	}
	l.Charge("k")
	l.Charge("k")
	if l.Ready("k") {
		t.Fatal("после двух неудач попыток нет")
	}
}

func TestRetryInNamesTheWait(t *testing.T) {
	l := New(1, 1, time.Minute)
	if l.RetryIn("k") != 0 {
		t.Fatal("попытка есть — ждать нечего")
	}
	l.Allow("k")
	if w := l.RetryIn("k"); w <= 50*time.Second || w > time.Minute {
		t.Fatalf("ведро на одну попытку в минуту пусто: ждать около минуты, а не %v", w)
	}
}
