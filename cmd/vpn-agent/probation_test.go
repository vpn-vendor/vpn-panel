package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/health"
)

var allHealthy = map[string]bool{
	"service-crash-loop": false, "intent-broken": false,
	"killswitch-down": false, "data-stuck": false,
}

func tempProbation(t *testing.T) {
	t.Helper()
	d := t.TempDir()
	og, op, or, oh := releaseGoodFile, probationFile, rollbackIntentFile, heldDebDir
	releaseGoodFile = filepath.Join(d, "good.json")
	probationFile = filepath.Join(d, "prob.json")
	rollbackIntentFile = filepath.Join(d, "intent.json")
	heldDebDir = filepath.Join(d, "rollback")
	t.Cleanup(func() {
		releaseGoodFile, probationFile, rollbackIntentFile, heldDebDir = og, op, or, oh
	})
}

func watch(version string, bad map[string]bool, now *time.Time) *probationWatch {
	return &probationWatch{
		version:    func() string { return version },
		readings:   func(int) (map[string]bool, int) { return bad, 0 },
		holdDeb:    func(v string) string { return heldDebDir + "/vpn-panel_" + v + ".deb" },
		fairChance: func() time.Duration { return time.Minute },
		now:        func() time.Time { return *now },
		stop:       make(chan struct{}),
	}
}

func TestFreshHealthyConfirmed(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	g := readReleaseGood()
	if g == nil || g.Version != "0.3.3" {
		t.Fatalf("свежая здоровая версия не подтверждена: %+v", g)
	}
}

func TestFreshCatastropheNotConfirmed(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	bad := map[string]bool{"service-crash-loop": true}
	watch("0.3.3", bad, &now).step()
	if readReleaseGood() != nil {
		t.Fatal("сломанная свежая версия не должна становиться якорем")
	}
}

func TestUpdateCatastropheRollbackIntent(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()

	bad := map[string]bool{"intent-broken": true}
	watch("0.3.4", bad, &now).step()

	ri := readRollbackIntent()
	if ri == nil || ri.ToVersion != "0.3.3" {
		t.Fatalf("нет намерения отката на якорь: %+v", ri)
	}
	prob := readProbation()
	if prob == nil || prob.Phase != phaseRollback {
		t.Fatalf("фаза не rollback_pending: %+v", prob)
	}
}

func TestUpdateSoftAwaits(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()

	watch("0.3.4", map[string]bool{"data-stuck": true}, &now).step()

	if readRollbackIntent() != nil {
		t.Fatal("мягкая деградация не должна писать намерение отката")
	}
	if prob := readProbation(); prob == nil || prob.Phase != phaseAwait {
		t.Fatalf("фаза не await: %+v", prob)
	}
}

func TestPreexistingNotRolledBack(t *testing.T) {
	tempProbation(t)
	now := time.Now()

	watch("0.3.3", map[string]bool{"data-stuck": true}, &now).step()

	watch("0.3.4", map[string]bool{"data-stuck": true}, &now).step()
	if readRollbackIntent() != nil {
		t.Fatal("дефект, бывший на якоре, не повод к откату")
	}
}

func TestHealthySustainedPromotes(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()

	w := watch("0.3.4", allHealthy, &now)
	w.step()
	if readReleaseGood().Version != "0.3.3" {
		t.Fatal("повысили до истечения окна")
	}
	now = now.Add(2 * time.Minute)
	w.step()
	if g := readReleaseGood(); g == nil || g.Version != "0.3.4" {
		t.Fatalf("здоровая версия не повышена после окна: %+v", g)
	}
	if readProbation() != nil {
		t.Fatal("испытательный срок не снят после подтверждения")
	}
}

func TestSameVersionNoProbation(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	watch("0.3.3", allHealthy, &now).step()
	if readProbation() != nil {
		t.Fatal("на подтверждённой версии испытательного срока быть не должно")
	}
}

func TestReleaseStatusDTO(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	w := watch("0.3.4", map[string]bool{"intent-broken": true}, &now)
	w.step()
	res, rpcErr := w.releaseStatus(nil)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	dto := res.(probationStatusDTO)
	if dto.Phase != phaseRollback || dto.Anchor != "0.3.3" || len(dto.Reasons) == 0 {
		t.Fatalf("статус не отражает откат: %+v", dto)
	}
}

func TestProbesMatchRegistry(t *testing.T) {
	known := map[string]bool{}
	for _, c := range health.Registry() {
		known[c.Name] = true
	}
	for _, p := range healthProbes {
		if !known[p.name] {
			t.Errorf("датчик %q не объявлен в реестре ядра", p.name)
		}
	}
}

func TestReadingsFromFacts(t *testing.T) {
	stopped := healthFacts{PanelKnown: true, Panel: unitState{Active: "inactive", Sub: "dead", Result: "success", Burst: 5}}
	if r := readingsFrom(stopped, 0); r["service-crash-loop"] || r["service-restarted"] {
		t.Fatalf("остановленная панель — обслуживание: %v", r)
	}
	once := healthFacts{PanelKnown: true, Panel: unitState{Active: "active", Restarts: 1, Burst: 5}}
	if r := readingsFrom(once, 0); r["service-crash-loop"] || !r["service-restarted"] {
		t.Fatalf("один перезапуск — мягкий признак: %v", r)
	}
	loop := healthFacts{PanelKnown: true, Panel: unitState{Active: "active", Restarts: 5, Burst: 5}}
	if r := readingsFrom(loop, 0); !r["service-crash-loop"] {
		t.Fatalf("перезапусков не меньше предела — цикл: %v", r)
	}

	if r := readingsFrom(loop, noRestartBase); r["service-crash-loop"] || r["service-restarted"] {
		t.Fatalf("без базы считается только отказ: %v", r)
	}
	served := healthFacts{PanelKnown: true, Panel: unitState{Active: "active"}, PanelServes: false}
	if r := readingsFrom(served, noRestartBase); !r["panel-unserved"] {
		t.Fatalf("запущенная панель без соединений — мягкий признак: %v", r)
	}
	masked := healthFacts{PanelKnown: true, Panel: unitState{Active: "inactive"}, PanelServes: false}
	if r := readingsFrom(masked, noRestartBase); r["panel-unserved"] {
		t.Fatalf("остановленная панель не «не отдаёт страницу»: %v", r)
	}
	db := healthFacts{DBKnown: true, DBIntact: false}
	if r := readingsFrom(db, noRestartBase); !r["db-corrupt"] {
		t.Fatalf("повреждённая база — катастрофа: %v", r)
	}
	if r := readingsFrom(healthFacts{DBIntact: false}, noRestartBase); r["db-corrupt"] {
		t.Fatalf("непроверенная база не считается повреждённой: %v", r)
	}
	ks := healthFacts{VPN: map[string]any{"mode": modeBlack, "outbound_guard": false}}
	if r := readingsFrom(ks, noRestartBase); !r["killswitch-down"] {
		t.Fatalf("защищённый режим без защиты выхода: %v", r)
	}
}

func TestRestartedAwaitsDecision(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	watch("0.3.4", map[string]bool{"service-restarted": true}, &now).step()
	if prob := readProbation(); prob == nil || prob.Phase != phaseAwait {
		t.Fatalf("перезапуск после обновления должен давать await: %+v", prob)
	}
	if readRollbackIntent() != nil {
		t.Fatal("мягкий признак не пишет намерение отката")
	}
}

func TestRestartBaseTracksCounter(t *testing.T) {
	tempProbation(t)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	w := watch("0.3.4", allHealthy, &now)
	restarts := 3
	w.readings = func(int) (map[string]bool, int) { return allHealthy, restarts }
	w.step()
	if p := readProbation(); p == nil || p.RestartBase != 3 {
		t.Fatalf("база должна быть снята в начале срока: %+v", p)
	}
	restarts = 0
	w.step()
	if p := readProbation(); p == nil || p.RestartBase != 0 {
		t.Fatalf("база не выше счётчика: %+v", p)
	}
}

func TestIntentCarriesFromAndBackup(t *testing.T) {
	tempRollback(t)
	_ = os.WriteFile(panelDBPath+".bak-20260102000000", []byte("pre-bad"), 0o600)
	now := time.Now()
	watch("0.3.3", allHealthy, &now).step()
	watch("0.3.4", map[string]bool{"intent-broken": true}, &now).step()
	i := readRollbackIntent()
	if i == nil || i.FromVersion != "0.3.4" || i.DBBackup != panelDBPath+".bak-20260102000000" {
		t.Fatalf("намерение неполно: %+v", i)
	}
}

func TestIntentKicksIdleExecutor(t *testing.T) {
	tempRollback(t)
	writeIntent(t, rollbackIntent{ToVersion: "0.3.3"})
	now := time.Now()
	calls := 0
	w := watch("0.3.4", allHealthy, &now)
	w.trigger = func() { calls++ }
	w.units = fakeUnits(map[string]unitState{rollbackUnit: {Active: "inactive"}}, nil)
	w.step()
	w.step()
	if calls != 2 {
		t.Fatalf("простаивающего исполнителя зовут на каждом такте, вызовов %d", calls)
	}
	w.units = fakeUnits(map[string]unitState{rollbackUnit: {Active: "activating"}}, nil)
	w.step()
	if calls != 2 {
		t.Fatal("работающего исполнителя дёргать нельзя")
	}
	if readProbation() != nil && readProbation().Phase == phaseObserving {
		t.Fatal("при незавершённом откате версия не судится")
	}
}
