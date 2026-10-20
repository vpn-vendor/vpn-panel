package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
)

func tempRollback(t *testing.T) {
	t.Helper()
	tempProbation(t)
	d := t.TempDir()
	oo, od := rollbackOutcomeFile, panelDBPath
	rollbackOutcomeFile = filepath.Join(d, "outcome.json")
	panelDBPath = filepath.Join(d, "panel.sqlite")
	t.Cleanup(func() { rollbackOutcomeFile, panelDBPath = oo, od })
}

func writeIntent(t *testing.T, i rollbackIntent) {
	t.Helper()
	data, _ := json.Marshal(i)
	if err := durable.Write(rollbackIntentFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeUnits(states map[string]unitState, order *[]string) *unitOps {
	act := func(name string) func(string) error {
		return func(u string) error {
			if order != nil {
				*order = append(*order, name)
			}
			return nil
		}
	}
	return &unitOps{
		wait: func(time.Duration) {},
		state: func(u string) (unitState, error) {
			st, ok := states[u]
			if !ok {
				return unitState{}, errors.New("нет такой службы")
			}
			return st, nil
		},
		stop: act("stop"), start: act("start"), mask: act("mask"), unmask: act("unmask"), resetFailed: act("reset-failed"),
	}
}

func orderExec(order *[]string) *rollbackExec {
	return &rollbackExec{
		installed:   func() string { return "0.3.4" },
		units:       fakeUnits(nil, order),
		lockFree:    func() bool { return true },
		dpkgInstall: func(string) error { *order = append(*order, "dpkg"); return nil },
		aptInstall:  func(string) error { *order = append(*order, "apt"); return nil },
		restoreDB:   func(string) error { *order = append(*order, "restore"); return nil },
		holdPkg:     func() error { *order = append(*order, "hold"); return nil },
		now:         time.Now,
	}
}

func TestRollbackOrder(t *testing.T) {
	tempRollback(t)
	_ = durable.MkdirAll(heldDebDir, 0o750)
	deb := filepath.Join(heldDebDir, "vpn-panel_0.3.3.deb")
	if err := os.WriteFile(deb, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var order []string
	ex := orderExec(&order)
	out := ex.run(&rollbackIntent{ToVersion: "0.3.3", DebPath: deb}, 1)
	want := []string{"stop", "mask", "dpkg", "restore", "hold", "unmask", "start"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("порядок %v, ждём %v", order, want)
	}
	if out.Kind != "rolled_back" {
		t.Fatalf("итог %s", out.Kind)
	}
}

func TestRollbackSkipsInstallWhenOnTarget(t *testing.T) {
	tempRollback(t)
	var order []string
	ex := orderExec(&order)
	ex.installed = func() string { return "0.3.3" }
	ex.run(&rollbackIntent{ToVersion: "0.3.3", DebPath: "/нет"}, 1)
	for _, s := range order {
		if s == "dpkg" || s == "apt" {
			t.Fatalf("на целевой версии установка не нужна: %v", order)
		}
	}
}

func TestRollbackFallsBackToApt(t *testing.T) {
	tempRollback(t)
	var order []string
	ex := orderExec(&order)
	ex.run(&rollbackIntent{ToVersion: "0.3.3", DebPath: ""}, 1)
	has := map[string]bool{}
	for _, s := range order {
		has[s] = true
	}
	if has["dpkg"] || !has["apt"] {
		t.Fatalf("без локального .deb ждём apt, не dpkg: %v", order)
	}
}

func TestRollbackInstallFailLimp(t *testing.T) {
	tempRollback(t)
	_ = durable.MkdirAll(heldDebDir, 0o750)
	deb := filepath.Join(heldDebDir, "vpn-panel_0.3.3.deb")
	_ = os.WriteFile(deb, []byte("x"), 0o600)
	var order []string
	ex := orderExec(&order)
	ex.dpkgInstall = func(string) error { return errors.New("boom") }
	out := ex.run(&rollbackIntent{ToVersion: "0.3.3", DebPath: deb}, 1)
	if out.Kind != "limp" {
		t.Fatalf("провал установки должен давать limp, получили %s", out.Kind)
	}

	for _, s := range order {
		if s == "restore" {
			t.Fatal("база восстановлена при проваленной установке — это половина отката")
		}
	}
}

func TestRollbackBucketLimp(t *testing.T) {
	tempRollback(t)
	writeIntent(t, rollbackIntent{ToVersion: "0.3.3"})
	writeOutcome(rollbackOutcome{Kind: "rolled_back", ToVersion: "0.3.3", Attempts: rollbackMaxAttempts})
	if rc := runRollback(); rc == 0 {
		t.Fatal("после предела попыток ожидали отказ")
	}
	if o := readOutcome(); o == nil || o.Kind != "limp" {
		t.Fatalf("не ушли в limp после предела попыток: %+v", o)
	}
}

func TestLimpStopsAutoAction(t *testing.T) {
	tempRollback(t)
	writeOutcome(rollbackOutcome{Kind: "limp", ToVersion: "0.3.3"})
	now := time.Now()
	watch("0.3.4", map[string]bool{"intent-broken": true}, &now).step()
	if readRollbackIntent() != nil {
		t.Fatal("в limp авто-откат запрещён")
	}
}

func TestSynthFromGoodNone(t *testing.T) {
	tempRollback(t)
	if synthFromGood() != nil {
		t.Fatal("без якоря откатывать некуда")
	}
}

func TestSynthFromGoodBuilds(t *testing.T) {
	tempRollback(t)
	data, _ := json.Marshal(releaseGood{Version: "9.9.9", DebPath: "/x.deb"})
	if err := durable.Write(releaseGoodFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	i := synthFromGood()
	if i == nil || i.ToVersion != "9.9.9" || len(i.Reasons) == 0 {
		t.Fatalf("синтез отката из якоря не сработал: %+v", i)
	}
}

func TestVerifyAfterRollbackLimp(t *testing.T) {
	tempRollback(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	writeOutcome(rollbackOutcome{Kind: "rolled_back", ToVersion: "0.3.3", Attempts: 1})
	bad := map[string]bool{"service-crash-loop": true, "intent-broken": false, "killswitch-down": false, "data-stuck": false}
	watch("0.3.3", bad, &now).step()
	if o := readOutcome(); o == nil || o.Kind != "limp" {
		t.Fatalf("обе стороны плохи — ожидали limp: %+v", o)
	}
}

func TestWatchdogIgnoresSingleCrash(t *testing.T) {
	tempRollback(t)
	data, _ := json.Marshal(releaseGood{Version: "0.3.3", DebPath: "/x.deb"})
	_ = durable.Write(releaseGoodFile, data, 0o600)
	var order []string
	old := rollbackUnits
	rollbackUnits = fakeUnits(map[string]unitState{
		panelService: {Active: "activating", Sub: "auto-restart", Result: "exit-code", Restarts: 1, Burst: 5},
		agentUnit:    {Active: "active", Sub: "running", Result: "success"},
	}, &order)
	t.Cleanup(func() { rollbackUnits = old })
	if rc := runRollback(); rc != 0 {
		t.Fatalf("одиночное падение — не повод действовать, код %d", rc)
	}
	if readRollbackIntent() != nil || len(order) != 0 {
		t.Fatalf("на одиночном падении ничего не должно происходить: намерение %v, действия %v", readRollbackIntent(), order)
	}
}

func TestWatchdogRevivesWhenNothingToRollBack(t *testing.T) {
	tempRollback(t)
	var order []string
	old := rollbackUnits
	rollbackUnits = fakeUnits(map[string]unitState{
		panelService: {Active: "failed", Sub: "failed", Result: "start-limit-hit", Restarts: 5, Burst: 5},
		agentUnit:    {Active: "active", Sub: "running", Result: "success"},
	}, &order)
	t.Cleanup(func() { rollbackUnits = old })
	if rc := runRollback(); rc != 0 {
		t.Fatalf("код %d", rc)
	}
	if !reflect.DeepEqual(order, []string{"reset-failed", "start"}) {
		t.Fatalf("ждали сброс отказа и старт, получили %v", order)
	}
}

func TestWatchdogWritesIntentFirst(t *testing.T) {
	tempRollback(t)
	data, _ := json.Marshal(releaseGood{Version: "0.3.3", DebPath: "/нет.deb"})
	_ = durable.Write(releaseGoodFile, data, 0o600)
	_ = os.WriteFile(panelDBPath+".bak-20260101000000", []byte("old"), 0o600)
	_ = os.WriteFile(panelDBPath+".bak-20260102000000", []byte("pre-bad"), 0o600)
	oldUnits, oldExec := rollbackUnits, newRollbackExec
	rollbackUnits = fakeUnits(map[string]unitState{
		panelService: {Active: "failed", Result: "start-limit-hit", Restarts: 5, Burst: 5},
		agentUnit:    {Active: "active", Result: "success"},
	}, nil)
	var seen *rollbackIntent
	var restored string
	newRollbackExec = func() *rollbackExec {
		ex := orderExec(&[]string{})
		ex.installed = func() string { return "9.9.9" }
		ex.aptInstall = func(string) error { seen = readRollbackIntent(); return nil }
		ex.restoreDB = func(b string) error { restored = b; return nil }
		return ex
	}
	t.Cleanup(func() { rollbackUnits, newRollbackExec = oldUnits, oldExec })

	if rc := runRollback(); rc != 0 {
		t.Fatalf("код %d: %+v", rc, readOutcome())
	}
	if seen == nil {
		t.Fatal("к моменту установки намерение должно уже лежать на диске")
	}
	if seen.DBBackup != panelDBPath+".bak-20260102000000" || restored != seen.DBBackup {
		t.Fatalf("копия базы в намерении %q, восстановлена %q", seen.DBBackup, restored)
	}
	if o := readOutcome(); o == nil || o.Kind != "rolled_back" || o.FromVersion != "" && o.FromVersion != seen.FromVersion {
		t.Fatalf("итог: %+v", o)
	}
}

func TestRestoreNamedBackupDropsWAL(t *testing.T) {
	tempRollback(t)
	pre := panelDBPath + ".bak-20260102000000"
	_ = os.WriteFile(pre, []byte("pre-bad"), 0o600)
	_ = os.WriteFile(panelDBPath+".bak-20260103000000", []byte("post-bad"), 0o600)
	_ = os.WriteFile(panelDBPath+"-wal", []byte("stale"), 0o600)
	_ = os.WriteFile(panelDBPath+"-shm", []byte("stale"), 0o600)
	if err := restoreBackup(pre); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(panelDBPath) //nolint:gosec
	if string(got) != "pre-bad" {
		t.Fatalf("восстановлена не та копия: %q", got)
	}
	if fileExists(panelDBPath+"-wal") || fileExists(panelDBPath+"-shm") {
		t.Fatal("устаревшие -wal/-shm должны быть убраны")
	}
}

func TestGateHoldsAfterRollback(t *testing.T) {
	held := true
	var acts []string
	cmp := func(a, op, b string) bool {
		order := map[string]int{"0.3.3": 1, "0.3.4": 2, "0.3.5": 3}
		switch op {
		case "ge":
			return order[a] >= order[b]
		case "gt":
			return order[a] > order[b]
		}
		return false
	}
	from := "0.3.4"
	g := &versionGate{
		ceiling:        func() string { return "0.3.4" },
		installed:      func() string { return "0.3.3" },
		held:           func() bool { return held },
		hold:           func() error { acts = append(acts, "hold"); held = true; return nil },
		unhold:         func() error { acts = append(acts, "unhold"); held = false; return nil },
		cmp:            cmp,
		rolledBackFrom: func() string { return from },
	}
	g.onPolicyChange()
	if len(acts) != 0 {
		t.Fatalf("потолок равен плохой версии — hold должен остаться: %v", acts)
	}

	g.ceiling = func() string { return "0.3.5" }
	g.onPolicyChange()
	if !reflect.DeepEqual(acts, []string{"unhold"}) {
		t.Fatalf("потолок выше плохой версии — ждали unhold: %v", acts)
	}
}

func TestWatchdogIgnoresTransientFailed(t *testing.T) {
	tempRollback(t)
	data, _ := json.Marshal(releaseGood{Version: "0.3.3", DebPath: "/x.deb"})
	_ = durable.Write(releaseGoodFile, data, 0o600)
	reads := 0
	old := rollbackUnits
	rollbackUnits = &unitOps{
		wait: func(time.Duration) {},
		state: func(u string) (unitState, error) {
			if u != panelService {
				return unitState{Active: "active"}, nil
			}
			reads++
			if reads == 1 {
				return unitState{Active: "failed", Result: "exit-code", Restarts: 1, Burst: 5}, nil
			}
			return unitState{Active: "activating", Sub: "auto-restart", Result: "exit-code", Restarts: 1, Burst: 5}, nil
		},
	}
	t.Cleanup(func() { rollbackUnits = old })
	if rc := runRollback(); rc != 0 || readRollbackIntent() != nil {
		t.Fatalf("мгновенный failed перед auto-restart — не повод: код %d, намерение %v", rc, readRollbackIntent())
	}
}

func TestWatchdogLimpWhenAnchorFailsAfterRollback(t *testing.T) {
	tempRollback(t)
	writeOutcome(rollbackOutcome{Kind: "rolled_back", ToVersion: "", FromVersion: "9.9.9", Attempts: 1})

	var order []string
	old := rollbackUnits
	rollbackUnits = fakeUnits(map[string]unitState{
		panelService: {Active: "failed", Result: "exit-code", Restarts: 4, Burst: 5},
		agentUnit:    {Active: "active"},
	}, &order)
	t.Cleanup(func() { rollbackUnits = old })
	_ = runRollback()
	if o := readOutcome(); o == nil || o.Kind != "limp" || o.FromVersion != "9.9.9" {
		t.Fatalf("обе стороны плохи — ждали limp: %+v", o)
	}
	if len(order) != 0 {
		t.Fatalf("в limp оживлять нельзя: %v", order)
	}

	_ = runRollback()
	if len(order) != 0 {
		t.Fatalf("терминальный режим — никаких действий: %v", order)
	}
}

func TestRollbackDeferredWhileDpkgBusy(t *testing.T) {
	tempRollback(t)
	writeIntent(t, rollbackIntent{ToVersion: "0.3.3", DebPath: "/нет.deb"})
	oldExec := newRollbackExec
	var order []string
	newRollbackExec = func() *rollbackExec {
		ex := orderExec(&order)
		ex.lockFree = func() bool { return false }
		ex.units = fakeUnits(map[string]unitState{panelService: {Active: "failed", Window: time.Minute, Pause: time.Second}}, &order)
		tick := time.Now()
		ex.now = func() time.Time { tick = tick.Add(30 * time.Second); return tick }
		return ex
	}
	t.Cleanup(func() { newRollbackExec = oldExec })
	if rc := runRollback(); rc == 0 {
		t.Fatal("отложенный откат не должен выглядеть удачным")
	}
	if readOutcome() != nil {
		t.Fatalf("отложенный откат не пишет итог: %+v", readOutcome())
	}
	if readRollbackIntent() == nil {
		t.Fatal("намерение должно остаться для следующего такта")
	}
	for _, s := range order {
		if s == "dpkg" || s == "apt" || s == "restore" {
			t.Fatalf("при занятом замке ставить нельзя: %v", order)
		}
	}
}
