package diag

import (
	"errors"
	"testing"
	"time"
)

func TestLanTestSessionBoundFromStart(t *testing.T) {
	LanTestReset()
	t0 := time.Unix(1_700_000_000, 0)
	fresh, err := lanTestSessionAt(t0, "10.0.0.5", 3*time.Second)
	if err != nil || !fresh {
		t.Fatalf("открытие: %v %v", fresh, err)
	}
	for i := 1; i <= 40; i++ {
		fresh, err = lanTestSessionAt(t0.Add(time.Duration(i)*100*time.Millisecond), "10.0.0.5", 3*time.Second)
		if err != nil || fresh {
			t.Fatalf("внутри сеанса запрос %d: %v %v", i, fresh, err)
		}
	}
	if _, err := lanTestSessionAt(t0.Add(3*time.Second+LanTestDataGrace+time.Millisecond), "10.0.0.5", 3*time.Second); !errors.Is(err, ErrLanTestExpired) {
		t.Fatalf("после срока данные обязаны прекратиться: %v", err)
	}
	if _, err := lanTestSessionAt(t0.Add(time.Second), "10.0.0.6", 3*time.Second); !errors.Is(err, ErrLanTestBusy) {
		t.Fatalf("чужой адрес во время сеанса: %v", err)
	}
	after := t0.Add(3*time.Second + LanTestDataGrace + LanTestLockGrace + time.Second)
	if _, err := lanTestSessionAt(after, "10.0.0.6", 3*time.Second); !errors.Is(err, ErrLanTestCooldown) {
		t.Fatalf("общий перерыв после сеанса: %v", err)
	}
	if _, err := lanTestSessionAt(after, "10.0.0.5", 3*time.Second); !errors.Is(err, ErrLanTestCooldown) {
		t.Fatalf("перерыв действует и на прежний адрес: %v", err)
	}
	fresh, err = lanTestSessionAt(t0.Add(3*time.Second+LanTestCooldown+time.Second), "10.0.0.6", 3*time.Second)
	if err != nil || !fresh {
		t.Fatalf("после перерыва новый сеанс: %v %v", fresh, err)
	}
	if LanTestCooldown != 2*time.Minute || LanTestDataGrace != 2*time.Second || LanTestLockGrace != 20*time.Second {
		t.Fatal("сроки сеанса изменены")
	}
}
