package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftwatch"
	"github.com/vpn-vendor/vpn-panel-core/internal/sockowner"
)

const (
	guardSettle = surroundEvery / surroundShare

	guardPauseFirst = surroundEvery / surroundShare

	guardPauseMax = time.Hour

	guardCalm = guardPauseMax
)

const ipForwardFile = "/proc/sys/net/ipv4/ip_forward"

type tableShape struct {
	present bool
	handle  int64
	body    string
}

func (a tableShape) same(b tableShape) bool { return a.present == b.present && a.body == b.body }

type writer struct {
	pid  int
	comm string
	unit string
}

type tableGuard struct {
	shape tableShape

	emergency      bool
	emergencyShape tableShape

	failed bool

	reopenedAt time.Time
	pause      time.Duration
	next       time.Time

	erasedAt time.Time
	eraser   writer
	erasures int
	returns  int

	fwdPause    time.Duration
	fwdNext     time.Time
	fwdOffAt    time.Time
	fwdReturns  int
	fwdOffNow   bool
	wake        chan struct{}
	afterChange func()

	sys guardSys
}

type guardSys struct {
	now        func() time.Time
	shape      func() (tableShape, bool)
	load       func(ruleset []byte) error
	setForward func(on bool) bool
	forward    func() (on, ok bool)

	emergency func() []byte
}

func (g *tableGuard) system() guardSys {
	s := g.sys
	if s.now == nil {
		s.now = time.Now
	}
	if s.shape == nil {
		s.shape = readShape
	}
	if s.load == nil {
		s.load = loadRuleset
	}
	if s.setForward == nil {
		s.setForward = setForward
	}
	if s.forward == nil {
		s.forward = readForward
	}
	return s
}

func (g *tableGuard) now() time.Time { return g.system().now() }

func loadRuleset(ruleset []byte) error {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return err
	}
	if out, err := runStdin(nft, ruleset, "-f", "-"); err != nil {
		return &textError{firstLine(out)}
	}
	return nil
}

func grow(p time.Duration) time.Duration {
	if p == 0 {
		return guardPauseFirst
	}
	return min(2*p, guardPauseMax)
}

func (f *firewallApplier) startGuard(afterChange func()) {
	f.mu.Lock()
	f.guard.wake = make(chan struct{}, 1)
	f.guard.afterChange = afterChange
	f.mu.Unlock()
	go f.guardLoop()
}

func (f *firewallApplier) kickGuard() {
	f.mu.Lock()
	w := f.guard.wake
	f.mu.Unlock()
	if w == nil {
		return
	}
	select {
	case w <- struct{}{}:
	default:
	}
}

func (f *firewallApplier) guardLoop() {
	events, err := nftwatch.Subscribe(context.Background())
	if err != nil {

		log.Printf("firewall: rule change events unavailable: %v", err)
	}
	f.mu.Lock()
	wake := f.guard.wake
	f.mu.Unlock()
	self := selfUnit()
	var last writer
	timer := time.NewTimer(0)
	deadline := time.Now()
	for {
		timer.Reset(max(time.Until(deadline), 0))
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if w, foreign := eventWriter(ev, self); foreign {
				last = w
			}
			if d := time.Now().Add(guardSettle); d.Before(deadline) {
				deadline = d
			}
			continue
		case <-wake:
		case <-timer.C:
		}
		wait, changed := f.guardCheck(last)
		deadline = time.Now().Add(wait)
		if f.ensureDHCPWatch(last) {
			changed = true
		}
		if changed {
			f.mu.Lock()
			after := f.guard.afterChange
			f.mu.Unlock()
			if after != nil {
				after()
			}
		}
	}
}

func eventWriter(ev nftwatch.Event, self string) (writer, bool) {
	if ev.PID <= 0 || ev.PID == os.Getpid() || isOwnChild(ev.PID) {
		return writer{}, false
	}
	w := writer{pid: ev.PID, comm: ev.Comm}
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(ev.PID) + "/cgroup"); err == nil {
		w.unit = sockowner.UnitOf(raw)
	}
	if self != "" && w.unit == self {
		return writer{}, false
	}
	return w, true
}

func selfUnit() string {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	return sockowner.UnitOf(raw)
}

func (f *firewallApplier) guardCheck(last writer) (wait time.Duration, changed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &f.guard
	now := g.now()
	wait = surroundEvery
	if !g.erasedAt.IsZero() && !g.emergency && now.Sub(g.erasedAt) >= guardCalm {
		g.erasedAt, g.eraser, g.pause, g.failed = time.Time{}, writer{}, 0, false
		changed = true
	}
	if !g.fwdOffAt.IsZero() && !g.fwdOffNow && now.Sub(g.fwdOffAt) >= guardCalm {
		g.fwdOffAt, g.fwdPause = time.Time{}, 0
		changed = true
	}
	if f.held.ruleset == nil {

		if g.emergency {
			g.emergency = false
			changed = true
		}
		return wait, changed
	}
	f.recallPlan()
	cur, ok := g.system().shape()
	if !ok {
		return wait, changed
	}
	want := g.shape
	if g.emergency {
		want = g.emergencyShape
	}
	if cur.same(want) {
		if !g.emergency {
			return wait, f.guardForward(now) || changed
		}
		if now.Before(g.next) {
			return min(g.next.Sub(now), wait), changed
		}
		f.returnWorking(now)
		return min(g.pause, wait), true
	}
	g.erasedAt = now
	g.erasures++
	if last.pid != 0 {
		g.eraser = last
	}
	log.Printf("firewall: own table changed by someone else (%s)", writerLine(g.eraser))
	if now.Before(g.next) {

		f.loadEmergency()
		return min(g.next.Sub(now), wait), true
	}
	f.returnWorking(now)
	return min(g.pause, wait), true
}

func (f *firewallApplier) returnWorking(now time.Time) {
	g := &f.guard
	sys := g.system()
	g.pause = grow(g.pause)
	g.next = now.Add(g.pause)
	sys.setForward(false)
	if err := sys.load(f.held.ruleset); err != nil {
		log.Printf("firewall: own table not returned: %v", err)
		g.failed = true
		f.loadEmergency()
		return
	}
	g.shape, _ = sys.shape()
	if g.emergency {
		g.reopenedAt = now
	}
	g.emergency, g.failed = false, false
	f.held.gen++
	g.returns++
	if f.held.forward {
		sys.setForward(true)
	}
	log.Printf("firewall: own table returned, next return not before %s", g.pause)
}

func (f *firewallApplier) loadEmergency() {
	g := &f.guard
	sys := g.system()
	sys.setForward(false)
	g.emergency = true
	g.emergencyShape = tableShape{}
	var ruleset []byte
	if sys.emergency != nil {
		ruleset = sys.emergency()
	} else {
		ruleset = f.emergencyRuleset()
	}
	if ruleset == nil {
		return
	}
	if err := sys.load(ruleset); err != nil {

		log.Printf("firewall: emergency set not loaded: %v", err)
		g.emergencyShape, _ = sys.shape()
		return
	}
	g.emergencyShape, _ = sys.shape()
	log.Printf("firewall: emergency set loaded until the pause ends")
}

func (f *firewallApplier) emergencyRuleset() []byte {
	if f.composer != nil {
		if facts, ok := f.composer.FirewallFacts(); ok {
			if data := facts.Lockdown(); data != nil {
				return data
			}
		}
	}
	for _, p := range []string{lockdownFile, lockdownStatic} {
		if data, err := os.ReadFile(p); err == nil { //nolint:gosec
			return data
		}
	}
	return nil
}

func (f *firewallApplier) guardForward(now time.Time) bool {
	g := &f.guard
	if !f.held.forward || !f.held.working {
		g.fwdOffNow = false
		return false
	}
	sys := g.system()
	on, ok := sys.forward()
	if !ok || on {
		changed := g.fwdOffNow
		g.fwdOffNow = false
		return changed
	}
	g.fwdOffNow = true
	g.fwdOffAt = now
	if now.Before(g.fwdNext) {
		return true
	}
	g.fwdPause = grow(g.fwdPause)
	g.fwdNext = now.Add(g.fwdPause)
	if sys.setForward(true) {
		g.fwdOffNow = false
		g.fwdReturns++
		log.Printf("firewall: forwarding was switched off by someone else, switched back on")
	}
	return true
}

func setForward(on bool) bool {
	v := "net.ipv4.ip_forward=0"
	if on {
		v = "net.ipv4.ip_forward=1"
	}
	sysctl, err := findBinary([]string{"/usr/sbin/sysctl", "/sbin/sysctl"})
	if err == nil {
		err = exec.Command(sysctl, "-w", v).Run() //nolint:gosec
	}
	if err != nil {
		log.Printf("firewall: forwarding not switched: %v", err)
		return false
	}
	return true
}

func readForward() (on, ok bool) {
	raw, err := os.ReadFile(ipForwardFile)
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(raw)) == "1", true
}

func readShape() (tableShape, bool) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return tableShape{}, false
	}
	list, err := runOut(nft, "-j", "list", "tables")
	if err != nil {
		return tableShape{}, false
	}
	if !hasTable(list, "inet", "vpn_panel") {
		return tableShape{}, true
	}
	out, err := runOut(nft, "-j", "-t", "list", "table", "inet", "vpn_panel")
	if err != nil {

		return tableShape{}, true
	}
	return parseShape(out), true
}

func runOut(bin string, args ...string) ([]byte, error) {
	return runStdin(bin, nil, args...)
}

func hasTable(list []byte, family, name string) bool {
	var doc struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(list, &doc) != nil {
		return false
	}
	for _, it := range doc.Nftables {
		if it.Table != nil && it.Table.Family == family && it.Table.Name == name {
			return true
		}
	}
	return false
}

func parseShape(out []byte) tableShape {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return tableShape{present: true, body: "unreadable"}
	}
	s := tableShape{present: true}
	rules := map[string]int{}
	var parts []string
	for _, it := range doc.Nftables {
		for kind, raw := range it {
			var o struct {
				Name   string `json:"name"`
				Chain  string `json:"chain"`
				Handle int64  `json:"handle"`
				Type   any    `json:"type"`
				Hook   string `json:"hook"`
				Prio   any    `json:"prio"`
				Policy string `json:"policy"`
			}
			if json.Unmarshal(raw, &o) != nil {
				continue
			}
			switch kind {
			case "metainfo":
			case "table":
				s.handle = o.Handle
			case "rule":
				rules[o.Chain]++
			case "chain":
				prio, _ := json.Marshal(o.Prio)
				typ, _ := json.Marshal(o.Type)
				parts = append(parts, "chain "+o.Name+" "+string(typ)+" "+o.Hook+" "+string(prio)+" "+o.Policy)
			default:
				parts = append(parts, kind+" "+o.Name)
			}
		}
	}
	for chain, n := range rules {
		parts = append(parts, "rules "+chain+" "+strconv.Itoa(n))
	}
	sort.Strings(parts)
	s.body = strings.Join(parts, "\n")
	return s
}

func writerLine(w writer) string {
	if w.pid == 0 {
		return "unknown"
	}
	return "pid " + strconv.Itoa(w.pid) + " " + w.comm + " " + w.unit
}

var ownChildren struct {
	mu   sync.Mutex
	pids [64]int
	next int
}

func noteChild(pid int) {
	ownChildren.mu.Lock()
	defer ownChildren.mu.Unlock()
	ownChildren.pids[ownChildren.next] = pid
	ownChildren.next = (ownChildren.next + 1) % len(ownChildren.pids)
}

func isOwnChild(pid int) bool {
	ownChildren.mu.Lock()
	defer ownChildren.mu.Unlock()
	for _, p := range ownChildren.pids {
		if p == pid {
			return true
		}
	}
	return false
}

type guardView struct {
	held, working, forward bool

	witnessCaps       hostcaps.Answer
	plan              *heldPlan
	emergency, failed bool
	erasedAt          time.Time
	eraser            writer
	erasures, returns int
	fwdOffAt          time.Time
	fwdOffNow         bool
	fwdReturns        int
}

type heldPlan struct {
	lans, prefixes, exits []string
}

func (f *firewallApplier) guardView() guardView {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &f.guard
	f.recallPlan()
	v := guardView{held: f.held.ruleset != nil, working: f.held.working, forward: f.held.forward,
		witnessCaps: capsOf(f.caps).Answer("nft.forward_witness"),
		emergency:   g.emergency, failed: g.failed, erasedAt: g.erasedAt, eraser: g.eraser,
		erasures: g.erasures, returns: g.returns, fwdOffAt: g.fwdOffAt, fwdOffNow: g.fwdOffNow,
		fwdReturns: g.fwdReturns}
	if p := f.held.plan; p != nil {
		hp := &heldPlan{exits: p.Exits()}
		for _, l := range p.LANs {
			hp.lans = append(hp.lans, l.Name)
			hp.prefixes = append(hp.prefixes, l.CIDR)
		}
		v.plan = hp
	}
	return v
}

func (f *firewallApplier) guardHolds(stale time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &f.guard
	return g.emergency || (!g.reopenedAt.IsZero() && g.now().Sub(g.reopenedAt) < stale)
}
