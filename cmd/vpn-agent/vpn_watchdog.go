package main

import (
	"context"
	"log"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	watchdogTick = 15 * time.Second
	retryMin     = 30 * time.Second
	retryMax     = 5 * time.Minute

	handshakeWait = 8 * time.Second

	serverAttemptBudget = 2
)

func staleAfter(p vpndriver.Passport) int64 {
	d := p.StaleAfter()
	if d <= 0 {
		d = 3 * time.Minute
	}
	return int64(d / time.Second)
}

type watchdogState struct {
	Degraded   bool
	RetryInSec int64

	upSince bootInstant

	lastProof     bootInstant
	lastProofBoot string

	Session      int64
	SessionSince int64
	alive        bool

	dataSamples  []dataSample
	DataDead     bool
	DataSuspect  bool
	DataRestarts int64
	backoff      time.Duration
	nextTry      bootInstant

	servicesPending  bool
	reapplyNotBefore bootInstant

	Paused bool

	bootID string

	plan vpnPlan
}

func (v *vpnApplier) markServicesPending(pending bool) {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	v.watch.servicesPending = pending
	if !pending {
		v.watch.reapplyNotBefore = 0
	}
}

func (v *vpnApplier) markUp() {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	v.watch.upSince, v.watch.bootID = bootStamp()
	v.newSession()
}

func (v *vpnApplier) newSession() {
	v.watch.Session++
	v.watch.SessionSince = time.Now().Unix()
	v.watch.dataSamples, v.watch.DataDead, v.watch.DataSuspect = nil, false, false
	v.saveWatchdogMemory()
}

func (v *vpnApplier) noteProof(ageSec int64) {
	now, id := bootStamp()
	if id == "" {
		return
	}
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	v.watch.lastProof, v.watch.lastProofBoot = now.Add(-time.Duration(ageSec)*time.Second), id
}

func (v *vpnApplier) noteLiveness(alive bool) {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	if alive && !v.watch.alive {
		v.newSession()
	}
	v.watch.alive = alive
}

func (v *vpnApplier) watchdogSnapshot() watchdogState {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	st := v.watch
	if !st.nextTry.IsZero() {
		if now, ok := bootNow(); ok {
			if left := int64(st.nextTry.Sub(now).Seconds()); left > 0 {
				st.RetryInSec = left
			}
		}
	}
	return st
}

func (v *vpnApplier) restartWatchdog(st vpnState) {
	v.watchMu.Lock()
	if v.watchStop != nil {
		v.watchStop()
		v.watchStop = nil
	}
	if st.Plan.Mode != modeBlack {
		v.watch = watchdogState{plan: st.Plan}
		v.saveWatchdogMemory()
		v.watchMu.Unlock()
		return
	}

	v.watch = carryOverOnRestart(v.watch, loadWatchdogMemory(st.Plan))
	v.watch.plan = st.Plan
	if v.watch.backoff <= 0 {
		v.watch.backoff = retryMin
	}
	v.saveWatchdogMemory()
	ctx, cancel := context.WithCancel(context.Background())
	v.watchStop = cancel
	v.watchMu.Unlock()
	go v.watchdogLoop(ctx)
}

func carryOverOnRestart(prev, loaded watchdogState) watchdogState {
	loaded.servicesPending = prev.servicesPending
	loaded.reapplyNotBefore = 0
	loaded.upSince, loaded.bootID = prev.upSince, prev.bootID
	loaded.lastProof, loaded.lastProofBoot, loaded.alive = prev.lastProof, prev.lastProofBoot, prev.alive
	if prev.Session > loaded.Session {
		loaded.Session, loaded.SessionSince = prev.Session, prev.SessionSince
	}
	return loaded
}

func (v *vpnApplier) kickWatchdog() {
	select {
	case v.watchKick <- struct{}{}:
	default:
	}
}

func (v *vpnApplier) StopWatchdog() {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	if v.watchStop != nil {
		v.watchStop()
		v.watchStop = nil
	}
}

func (v *vpnApplier) watchdogLoop(ctx context.Context) {
	ticker := time.NewTicker(watchdogTick)
	defer ticker.Stop()
	for {

		var events <-chan struct{}
		st := v.readState()
		if e, ok := v.driver(&st).(eventful); ok {
			events = e.events()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.watchdogTick(ctx)
		case <-events:
			v.watchdogTick(ctx)
		case <-v.watchKick:
			v.watchdogTick(ctx)
		}
	}
}

type watchdogInput struct {
	Present     bool
	HandshakeOK bool
	AgeSec      int64
	UpForSec    int64
	OnFailure   string
	Degraded    bool
	DueForRetry bool

	ServicesPending bool
	ReapplyDue      bool
	SelfRetrying    bool

	StaleSec int64

	DataDead     bool
	DataRestarts int64

	ServerAttempts int64
	CanPause       bool
	Paused         bool
}

func (v *vpnApplier) ladder(ctx context.Context, st *vpnState) []remedy {
	return []remedy{
		{id: "recover", disrupt: disruptProcess, when: whenRecover,
			apply: func(ctx context.Context, st *vpnState) { v.tryRecover(ctx, *st) }},
		{id: "reapply", disrupt: disruptNone, when: whenReapply,
			apply: func(_ context.Context, st *vpnState) { v.resetBackoff(); v.reapplyServices(st) }},

		{id: "pause", disrupt: disruptSession, when: whenPause,
			apply: func(_ context.Context, st *vpnState) { v.pauseAttempts(st) }},
		{id: "data_restart", disrupt: disruptProcess, when: whenDataRestart,
			apply: func(ctx context.Context, st *vpnState) { v.restartForData(ctx, *st) }},
		{id: "healthy", disrupt: disruptNone, when: whenHealthy,
			apply: func(_ context.Context, _ *vpnState) { v.resetBackoff() }},
		{id: "degrade", disrupt: disruptOffice, when: whenDegrade,
			apply: func(_ context.Context, st *vpnState) { v.degrade(*st) }},
		{id: "retry", disrupt: disruptProcess, when: whenRetry,
			apply: func(ctx context.Context, st *vpnState) { v.retryTunnel(ctx, *st) }},
	}
}

func (v *vpnApplier) watchdogTick(ctx context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if ctx.Err() != nil {
		return
	}
	st := v.readState()
	if st.Plan.Mode != modeBlack || st.Plan.Slug == "" {
		return
	}

	in := v.collectFacts(st)
	v.noteLiveness(aliveByFacts(in))
	r := chooseRemedy(in, v.ladder(ctx, &st))
	if r == nil {
		return
	}

	if r.id != "healthy" {
		log.Printf("vpn: watchdog remedy %q (disruption: %s)", r.id, r.disrupt)
	}
	r.apply(ctx, &st)
}

func (v *vpnApplier) collectFacts(st vpnState) watchdogInput {
	drv := v.driver(&st)
	pass := drv.passport(st.Transport)
	f := drv.facts()
	stale := staleAfter(pass)
	if f.Connected && f.AgeSec <= stale {
		v.noteProof(f.AgeSec)
	}

	if out, in, ok := v.firewallEcho(); ok && f.Present && f.Connected {
		now, _ := bootNow()
		v.observeData(dataSample{at: now, echoOut: out, echoIn: in, payRx: f.PayloadRx, payTx: f.PayloadTx}, stale)
	} else {
		v.forgetData()
	}
	snap := v.watchdogSnapshot()
	in := watchdogInput{
		Present:     f.Present,
		OnFailure:   st.Plan.OnFailure,
		Degraded:    snap.Degraded,
		DueForRetry: v.dueForRetry(),
		UpForSec:    -1,

		SelfRetrying:    f.ProcRunning && pass.Liveness == vpndriver.LivenessProcess,
		StaleSec:        staleAfter(pass),
		ServerAttempts:  int64(f.FailCount),
		CanPause:        pass.CanPause,
		Paused:          snap.Paused,
		ServicesPending: snap.servicesPending || f.ServicesMissing,
		DataDead:        snap.DataDead,
		DataRestarts:    snap.DataRestarts,
		ReapplyDue:      due(snap.reapplyNotBefore),
	}
	if f.Connected {
		in.HandshakeOK, in.AgeSec = true, f.AgeSec
	} else {
		in.UpForSec = silentFor(snap)
	}
	return in
}

func silentFor(snap watchdogState) int64 {
	up := sinceBoot(snap.upSince, snap.bootID)
	proof := sinceBoot(snap.lastProof, snap.lastProofBoot)
	switch {
	case up < 0:
		return proof
	case proof < 0:
		return up
	case proof < up:
		return proof
	default:
		return up
	}
}

func (v *vpnApplier) reapplyServices(st *vpnState) {
	if _, aerr := v.applyBlackServices(st); aerr != nil {
		log.Printf("vpn: services not restored after the tunnel came back on its own: %s", aerr.Message)
		v.watchMu.Lock()
		v.watch.reapplyNotBefore = bootDeadline(retryMin)
		v.watchMu.Unlock()
		return
	}
	if err := v.writeState(*st); err != nil {
		log.Printf("vpn: state write after reapply: %v", err)
	}
	log.Printf("vpn: tunnel came back on its own, protected mode services restored")
}

func (v *vpnApplier) degrade(st vpnState) {
	v.bringDown(&st)
	if _, aerr := v.firewall.applyPlanDirect(st.White.Firewall); aerr != nil {
		log.Printf("vpn: watchdog could not switch to direct access: %s", aerr.Message)
		return
	}
	if _, aerr := v.dns.applyPlan(st.White.DNS); aerr != nil {
		log.Printf("vpn: watchdog could not switch the resolver: %s", aerr.Message)
	}
	if _, aerr := v.qos.applyAndPersist(st.White.QoS); aerr != nil {
		log.Printf("vpn: watchdog could not switch the queue: %s", aerr.Message)
	}
	v.watchMu.Lock()
	v.watch.Degraded = true
	v.watch.backoff = retryMin
	v.watch.nextTry = bootDeadline(retryMin)
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
	log.Printf("vpn: tunnel is dead, office released directly by administrator's choice")
}

func (v *vpnApplier) tryRecover(ctx context.Context, st vpnState) {
	if !v.dueForRetry() {
		return
	}
	if _, aerr := v.bringUp(&st); aerr != nil {
		v.growBackoff()
		return
	}
	if !v.waitHandshake(ctx, &st) {
		v.bringDown(&st)
		v.growBackoff()
		return
	}

	if _, aerr := v.applyBlackServices(&st); aerr != nil {
		log.Printf("vpn: watchdog could not restore protected mode: %s", aerr.Message)
		return
	}
	if err := v.writeState(st); err != nil {
		log.Printf("vpn: state write after recovery: %v", err)
	}
	v.watchMu.Lock()
	v.watch.Degraded = false
	v.watch.backoff = retryMin
	v.watch.nextTry = 0
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
	log.Printf("vpn: tunnel recovered, office is protected again")
}

func (v *vpnApplier) retryTunnel(ctx context.Context, st vpnState) {
	if !v.dueForRetry() {
		return
	}
	prevIP := st.EndpointIP

	v.bringDown(&st)
	if _, aerr := v.bringUp(&st); aerr != nil {
		if isStartRefused(aerr) {

			v.markGaveUp("служба отвергла запуск: слишком много стартов подряд")
			return
		}
		v.growBackoff()
		return
	}
	if st.EndpointIP != prevIP {
		log.Printf("vpn: endpoint address changed, reconnecting")
		if err := v.writeState(st); err != nil {
			log.Printf("vpn: state write after re-resolve: %v", err)
		}
	}
	if v.waitHandshake(ctx, &st) {

		if _, aerr := v.applyBlackServices(&st); aerr != nil {
			log.Printf("vpn: services not restored after reconnect: %s", aerr.Message)
		}
		v.resetBackoff()
		log.Printf("vpn: tunnel is back")
		return
	}
	v.growBackoff()
}

func (v *vpnApplier) waitHandshake(ctx context.Context, st *vpnState) bool {
	deadline := time.Now().Add(handshakeWait)
	drv := v.driver(st)
	stale := staleAfter(drv.passport(st.Transport))
	for time.Now().Before(deadline) {
		if f := drv.facts(); f.Connected && f.AgeSec <= stale {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	return false
}

func (v *vpnApplier) dueForRetry() bool {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	return due(v.watch.nextTry)
}

func (v *vpnApplier) growBackoff() {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	if v.watch.backoff <= 0 {
		v.watch.backoff = retryMin
	}
	v.watch.nextTry = bootDeadline(v.watch.backoff)
	if v.watch.backoff < retryMax {
		v.watch.backoff *= 2
		if v.watch.backoff > retryMax {
			v.watch.backoff = retryMax
		}
	}
	v.saveWatchdogMemory()
}

func (v *vpnApplier) resetBackoff() {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	v.watch.backoff = retryMin
	v.watch.nextTry = 0
	v.saveWatchdogMemory()
}

func (v *vpnApplier) markGaveUp(reason string) {
	v.watchMu.Lock()
	v.watch.Paused = true
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
	log.Printf("vpn: automatic attempts stopped: %s", reason)
}

func (v *vpnApplier) pauseAttempts(st *vpnState) {
	drv, ok := v.driver(st).(pausable)
	if !ok {
		return
	}
	if err := drv.pause("бюджет попыток к серверу исчерпан"); err != nil {
		log.Printf("vpn: could not pause connection attempts: %v", err)
		return
	}
	v.watchMu.Lock()
	v.watch.Paused = true
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
}
