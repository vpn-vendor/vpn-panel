package main

import (
	"testing"
	"time"
)

func TestParseUnitState(t *testing.T) {
	out := []byte("ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nNRestarts=3\nStartLimitBurst=5\nStartLimitIntervalUSec=10min\nRestartUSec=2s\n")
	st, err := parseUnitState(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Active != "activating" || st.Sub != "auto-restart" || st.Result != "exit-code" || st.Restarts != 3 || st.Burst != 5 || st.Window != 10*time.Minute || st.Pause != 2*time.Second {
		t.Fatalf("разбор: %+v", st)
	}
	if _, err := parseUnitState([]byte("NRestarts=0\n")); err == nil {
		t.Fatal("без ActiveState состояние не прочитано")
	}
}

func TestParseTimeSpan(t *testing.T) {
	cases := map[string]time.Duration{
		"10s": 10 * time.Second, "5min": 5 * time.Minute, "1min 30s": 90 * time.Second,
		"2h": 2 * time.Hour, "infinity": 0, "0": 0, "500ms": 500 * time.Millisecond, "7": 7 * time.Second,
	}
	for in, want := range cases {
		if got := parseTimeSpan(in); got != want {
			t.Errorf("%q: %v, ждём %v", in, got, want)
		}
	}
}

func TestCrashLoop(t *testing.T) {
	if !crashLoop(unitState{Active: "failed", Result: "start-limit-hit"}, 0) {
		t.Error("отказ службы — цикл")
	}
	if crashLoop(unitState{Active: "active", Restarts: 7, Burst: 5}, 7) {
		t.Error("перезапуски до базы не в счёт")
	}
	if !crashLoop(unitState{Active: "active", Restarts: 7, Burst: 5}, 2) {
		t.Error("пять перезапусков с базы — цикл")
	}
	if crashLoop(unitState{Active: "active", Restarts: 4, Burst: 5}, 0) {
		t.Error("меньше предела — не цикл")
	}
	if crashLoop(unitState{Active: "inactive", Sub: "dead", Result: "success"}, 0) {
		t.Error("остановленная руками служба — обслуживание, не цикл")
	}
}

func TestPanelLimiterFromUnit(t *testing.T) {
	ops := fakeUnits(map[string]unitState{panelUnit: {Active: "active", Burst: 3, Window: time.Hour}}, nil)
	p := newPanelApplier(ops)
	allowed := 0
	for i := 0; i < 5; i++ {
		if p.limiter.Allow("restart") {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("при пределе 3 за окно руками разрешено 2, получили %d", allowed)
	}
}
