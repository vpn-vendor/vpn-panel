package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/health"
)

var (
	releaseGoodFile    = "/var/lib/vpn-panel/release-good.json"
	probationFile      = "/var/lib/vpn-panel/release-probation.json"
	rollbackIntentFile = "/var/lib/vpn-panel/release-rollback.json"
	heldDebDir         = "/var/lib/vpn-panel/rollback"
)

const panelService = "vpn-panel.service"

const (
	phaseObserving = "observing"
	phaseAwait     = "await"
	phaseRollback  = "rollback_pending"
)

type releaseGood struct {
	Version     string          `json:"version"`
	DebPath     string          `json:"deb_path"`
	Anchor      map[string]bool `json:"anchor"`
	ConfirmedAt time.Time       `json:"confirmed_at"`
}

type probationRec struct {
	NewVersion   string    `json:"new_version"`
	AnchorVer    string    `json:"anchor_version"`
	StartedAt    time.Time `json:"started_at"`
	HealthySince time.Time `json:"healthy_since"`
	Phase        string    `json:"phase"`

	RestartBase int `json:"restart_base"`
}

type rollbackIntent struct {
	ToVersion   string    `json:"to_version"`
	FromVersion string    `json:"from_version"`
	DebPath     string    `json:"deb_path"`
	DBBackup    string    `json:"db_backup"`
	Reasons     []string  `json:"reasons"`
	CreatedAt   time.Time `json:"created_at"`
}

const noRestartBase = -1

type probationWatch struct {
	mu sync.Mutex

	readings   func(base int) (map[string]bool, int)
	version    func() string
	holdDeb    func(version string) string
	fairChance func() time.Duration
	now        func() time.Time
	trigger    func()
	units      *unitOps
	stop       chan struct{}
}

func (p *probationWatch) executorBusy() bool {
	if p.units == nil {
		return false
	}
	st, err := p.units.state(rollbackUnit)
	return err == nil && (st.Active == "active" || st.Active == "activating")
}

func (p *probationWatch) kickExecutor() {
	if p.executorBusy() || p.trigger == nil {
		return
	}
	p.trigger()
}

func (p *probationWatch) resumeRollback() {
	if out := readOutcome(); out != nil && out.Kind == "limp" {
		return
	}
	if readRollbackIntent() == nil {
		return
	}
	p.kickExecutor()
}

func catastrophic() map[string]bool {
	out := map[string]bool{}
	for _, c := range health.Registry() {
		if c.Class == health.UpdateFault && c.Severity == health.Catastrophic {
			out[c.Name] = true
		}
	}
	return out
}

func (p *probationWatch) step() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if out := readOutcome(); out != nil && out.Kind == "limp" {
		return
	}

	if readRollbackIntent() != nil {
		p.kickExecutor()
		return
	}
	running := p.version()
	if running == "" {
		return
	}
	good := readReleaseGood()
	prob := readProbation()
	onProbation := good != nil && good.Version != running
	base := noRestartBase
	if onProbation && prob != nil && prob.NewVersion == running {
		base = prob.RestartBase
	}
	bad, restarts := p.readings(base)

	if good == nil {
		if !anyCatastrophe(bad) {
			p.confirmGood(running, bad)
		}
		return
	}

	if good.Version == running {

		if out := readOutcome(); out != nil && out.Kind == "rolled_back" && anyCatastrophe(bad) {
			writeOutcome(rollbackOutcome{Kind: "limp", ToVersion: running,
				Reasons: out.Reasons, At: p.now(), Attempts: out.Attempts})
			log.Printf("probation: anchor %s also unhealthy after rollback — limp", running)
			return
		}
		_ = durable.Remove(probationFile)
		_ = durable.Remove(rollbackIntentFile)
		return
	}

	if prob == nil || prob.NewVersion != running {
		prob = &probationRec{NewVersion: running, AnchorVer: good.Version, StartedAt: p.now(), Phase: phaseObserving, RestartBase: restarts}
	} else if restarts < prob.RestartBase {

		prob.RestartBase = restarts
	}

	v := health.Judge(mergeAnchor(bad, good.Anchor))
	switch v.Decision {
	case health.Rollback:
		p.pendRollback(prob, good, v.Reasons)
	case health.AwaitDecision:
		prob.Phase = phaseAwait
		prob.HealthySince = time.Time{}
		writeProbation(prob)
	case health.Healthy:
		if prob.HealthySince.IsZero() {
			prob.HealthySince = p.now()
		}
		if p.now().Sub(prob.HealthySince) >= p.fairChance() {

			p.confirmGood(running, bad)
		} else {
			prob.Phase = phaseObserving
			writeProbation(prob)
		}
	}
}

func (p *probationWatch) confirmGood(version string, bad map[string]bool) {
	g := releaseGood{
		Version:     version,
		DebPath:     p.holdDeb(version),
		Anchor:      bad,
		ConfirmedAt: p.now(),
	}
	data, err := json.Marshal(g)
	if err != nil {
		log.Printf("probation: good release not marshaled: %v", err)
		return
	}
	if err := durable.Write(releaseGoodFile, append(data, '\n'), 0o600); err != nil {
		log.Printf("probation: good release not written: %v", err)
		return
	}
	_ = durable.Remove(probationFile)
	_ = durable.Remove(rollbackIntentFile)
	_ = durable.Remove(rollbackOutcomeFile)
}

func (p *probationWatch) pendRollback(prob *probationRec, good *releaseGood, reasons []string) {
	intent := &rollbackIntent{ToVersion: good.Version, FromVersion: prob.NewVersion, DebPath: good.DebPath,
		DBBackup: newestBackup(), Reasons: reasons, CreatedAt: p.now()}
	if err := writeRollbackIntent(intent); err != nil {
		log.Printf("probation: rollback intent not written: %v", err)
		return
	}
	prob.Phase = phaseRollback
	prob.HealthySince = time.Time{}
	writeProbation(prob)
	log.Printf("probation: rollback to %s triggered (%d reason(s))", good.Version, len(reasons))
	p.kickExecutor()
}

func (p *probationWatch) run() {
	for {
		p.step()
		interval := p.fairChance() / 4

		if interval < 15*time.Second {
			interval = 15 * time.Second
		}
		select {
		case <-p.stop:
			return
		case <-time.After(interval):
		}
	}
}

func (p *probationWatch) StopWatch() { close(p.stop) }

type probationStatusDTO struct {
	Phase   string   `json:"phase"`
	Running string   `json:"running"`
	Anchor  string   `json:"anchor"`
	Reasons []string `json:"reasons"`
}

func (p *probationWatch) releaseStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	dto := probationStatusDTO{Phase: "normal", Running: p.version()}

	if out := readOutcome(); out != nil {
		dto.Phase = out.Kind
		dto.Anchor = out.ToVersion
		dto.Reasons = out.Reasons
		return dto, nil
	}
	if prob := readProbation(); prob != nil {
		dto.Phase = prob.Phase
		dto.Anchor = prob.AnchorVer
		if ri := readRollbackIntent(); ri != nil {
			dto.Reasons = ri.Reasons
		}
	}
	return dto, nil
}

func (p *probationWatch) releaseAccept(json.RawMessage) (any, *agentrpc.ErrorObject) {
	p.mu.Lock()
	defer p.mu.Unlock()
	running := p.version()
	if running == "" {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInternalError,
			Message: "установленную версию прочитать не удалось — обновите страницу"}
	}
	bad, _ := p.readings(noRestartBase)
	p.confirmGood(running, bad)
	return map[string]any{"accepted": running}, nil
}

func mergeAnchor(bad map[string]bool, anchor map[string]bool) []health.Reading {
	out := make([]health.Reading, 0, len(bad))
	for name, now := range bad {
		out = append(out, health.Reading{Name: name, BadNow: now, BadOnAnchor: anchor[name]})
	}
	return out
}

func anyCatastrophe(bad map[string]bool) bool {
	cat := catastrophic()
	for name, now := range bad {
		if now && cat[name] {
			return true
		}
	}
	return false
}

func readReleaseGood() *releaseGood {
	data, err := os.ReadFile(releaseGoodFile) //nolint:gosec
	if err != nil {
		return nil
	}
	var g releaseGood
	if json.Unmarshal(data, &g) != nil || g.Version == "" {
		return nil
	}
	return &g
}

func readProbation() *probationRec {
	data, err := os.ReadFile(probationFile) //nolint:gosec
	if err != nil {
		return nil
	}
	var r probationRec
	if json.Unmarshal(data, &r) != nil || r.NewVersion == "" {
		return nil
	}
	return &r
}

func writeProbation(r *probationRec) {
	data, err := json.Marshal(r)
	if err != nil {
		log.Printf("probation: state not marshaled: %v", err)
		return
	}
	if err := durable.Write(probationFile, append(data, '\n'), 0o600); err != nil {
		log.Printf("probation: state not written: %v", err)
	}
}

func writeRollbackIntent(i *rollbackIntent) error {
	data, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return durable.Write(rollbackIntentFile, append(data, '\n'), 0o600)
}

func readRollbackIntent() *rollbackIntent {
	data, err := os.ReadFile(rollbackIntentFile) //nolint:gosec
	if err != nil {
		return nil
	}
	var ri rollbackIntent
	if json.Unmarshal(data, &ri) != nil || ri.ToVersion == "" {
		return nil
	}
	return &ri
}

type healthFacts struct {
	Panel       unitState
	PanelKnown  bool
	PanelServes bool
	PortTaken   bool
	DBKnown     bool
	DBIntact    bool
	VPN         map[string]any
}

var healthProbes = []struct {
	name string
	bad  func(f healthFacts, base int) bool
}{

	{"service-crash-loop", func(f healthFacts, base int) bool {
		return f.PanelKnown && crashLoop(f.Panel, restartBase(f, base))
	}},

	{"service-restarted", func(f healthFacts, base int) bool {
		return f.PanelKnown && f.Panel.Restarts > restartBase(f, base)
	}},

	{"panel-unserved", func(f healthFacts, _ int) bool {
		return f.PanelKnown && f.Panel.Active == "active" && !f.PanelServes && !f.PortTaken
	}},

	{"panel-port-taken", func(f healthFacts, _ int) bool { return f.PortTaken }},

	{"db-corrupt", func(f healthFacts, _ int) bool { return f.DBKnown && !f.DBIntact }},
	{"intent-broken", func(f healthFacts, _ int) bool { return vpnBool(f.VPN, "intent_broken") }},

	{"killswitch-down", func(f healthFacts, _ int) bool {
		return vpnString(f.VPN, "mode") == modeBlack && !vpnBool(f.VPN, "outbound_guard")
	}},

	{"data-stuck", func(f healthFacts, _ int) bool {
		budget := vpnInt(f.VPN, "data_restart_budget")
		return vpnBool(f.VPN, "data_dead") && budget > 0 && vpnInt(f.VPN, "data_restarts") >= budget
	}},
}

func restartBase(f healthFacts, base int) int {
	if base == noRestartBase {
		return f.Panel.Restarts
	}
	return base
}

func vpnBool(m map[string]any, key string) bool     { v, _ := m[key].(bool); return v }
func vpnInt(m map[string]any, key string) int       { v, _ := m[key].(int); return v }
func vpnString(m map[string]any, key string) string { v, _ := m[key].(string); return v }

func readingsFrom(f healthFacts, base int) map[string]bool {
	bad := make(map[string]bool, len(healthProbes))
	for _, p := range healthProbes {
		bad[p.name] = p.bad(f, base)
	}
	return bad
}

func gatherFacts(vpn *vpnApplier, units *unitOps, deep bool) healthFacts {
	var f healthFacts
	if st, err := units.state(panelService); err == nil {
		f.Panel, f.PanelKnown = st, true
		f.PortTaken = panelPortTaken() != ""
		f.PanelServes = !f.PortTaken && panelAnswers()
	}
	if res, rerr := vpn.vpnStatus(nil); rerr == nil {
		f.VPN, _ = res.(map[string]any)
	}
	if deep {
		f.DBKnown = true
		f.DBIntact = panelCommand("db:check").Run() == nil
	}
	return f
}

func fairChanceFrom(vpn *vpnApplier, units *unitOps) time.Duration {
	base := time.Minute
	if st, err := units.state(panelService); err == nil && st.Window > base {
		base = st.Window
	}
	if res, rerr := vpn.vpnStatus(nil); rerr == nil {
		if m, ok := res.(map[string]any); ok {
			retry, _ := m["retry_in_sec"].(int)
			budget, _ := m["data_restart_budget"].(int)
			if retry > 0 {
				if d := time.Duration(retry*(budget+1)) * time.Second; d > base {
					base = d
				}
			}
		}
	}
	if base > 15*time.Minute {
		base = 15 * time.Minute
	}
	return base
}

func holdDebFromCache(version string) string {
	matches, _ := filepath.Glob("/var/cache/apt/archives/vpn-panel_" + version + "_*.deb")
	if len(matches) == 0 {
		return ""
	}
	data, err := os.ReadFile(matches[0]) //nolint:gosec
	if err != nil {
		return ""
	}
	if err := durable.MkdirAll(heldDebDir, 0o750); err != nil {
		log.Printf("probation: hold dir: %v", err)
		return ""
	}
	dst := heldDebDir + "/vpn-panel_" + version + ".deb"
	if err := durable.Write(dst, data, 0o644); err != nil {
		log.Printf("probation: held deb not written: %v", err)
		return ""
	}
	return dst
}
