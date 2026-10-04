package main

import "context"

type disruption uint8

const (
	disruptNone disruption = iota
	disruptSession
	disruptProcess
	disruptOffice
)

func (d disruption) String() string {
	switch d {
	case disruptSession:
		return "session"
	case disruptProcess:
		return "process"
	case disruptOffice:
		return "office"
	default:
		return "none"
	}
}

type remedy struct {
	id      string
	disrupt disruption

	when func(watchdogInput) bool

	apply func(ctx context.Context, st *vpnState)
}

func chooseRemedy(in watchdogInput, ladder []remedy) *remedy {
	for i := range ladder {
		if ladder[i].when(in) {
			return &ladder[i]
		}
	}
	return nil
}

func aliveByFacts(in watchdogInput) bool {
	stale := in.StaleSec
	if stale <= 0 {
		stale = 180
	}

	return (in.Present || in.SelfRetrying) && ((in.HandshakeOK && in.AgeSec <= stale) ||
		(!in.HandshakeOK && in.UpForSec >= 0 && in.UpForSec < stale))
}

func whenRecover(in watchdogInput) bool { return in.Degraded && in.DueForRetry }

func whenReapply(in watchdogInput) bool {

	return !in.Degraded && aliveByFacts(in) && in.ServicesPending && in.HandshakeOK && in.ReapplyDue
}

func whenHealthy(in watchdogInput) bool { return !in.Degraded && aliveByFacts(in) && !in.DataDead }

func whenDegrade(in watchdogInput) bool {
	return !in.Degraded && (!aliveByFacts(in) || in.DataDead) && in.OnFailure == failDirect
}

func whenDataRestart(in watchdogInput) bool {
	return !in.Degraded && in.OnFailure != failDirect && in.HandshakeOK && in.DataDead &&
		in.DataRestarts < dataRestartBudget
}

func whenPause(in watchdogInput) bool {
	return !in.Degraded && !in.HandshakeOK && in.OnFailure != failDirect &&
		in.ServerAttempts >= serverAttemptBudget && in.CanPause && in.SelfRetrying && !in.Paused
}

func whenRetry(in watchdogInput) bool {

	return !in.Degraded && !aliveByFacts(in) && in.OnFailure != failDirect &&
		in.ServerAttempts < serverAttemptBudget && !in.SelfRetrying && in.DueForRetry &&
		!in.Paused
}
