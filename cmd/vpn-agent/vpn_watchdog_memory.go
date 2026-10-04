package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const watchdogMemoryFile = "/var/lib/vpn-panel/agent-watchdog.json"

type watchdogMemory struct {
	Plan string `json:"plan"`

	Boot string `json:"boot"`

	Backoff time.Duration `json:"backoff"`

	NextTry          time.Duration `json:"next_try"`
	ReapplyNotBefore time.Duration `json:"reapply_not_before"`

	Degraded bool `json:"degraded"`

	Session      int64 `json:"session"`
	SessionSince int64 `json:"session_since"`

	DataRestarts int64 `json:"data_restarts"`
}

func planFingerprint(p vpnPlan) string {
	h := sha256.Sum256([]byte(p.Slug + "\x00" + p.Protocol + "\x00" + p.Mode +
		"\x00" + p.OnFailure + "\x00" + strconv.Itoa(p.MTU)))
	return hex.EncodeToString(h[:8])
}

func loadWatchdogMemory(p vpnPlan) watchdogState {
	data, err := os.ReadFile(watchdogMemoryFile) //nolint:gosec
	if err != nil {
		return watchdogState{}
	}
	var m watchdogMemory
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("vpn: watchdog memory is broken, starting careful: %v", err)
		return watchdogState{}
	}
	if m.Plan != planFingerprint(p) {

		return watchdogState{Session: m.Session, SessionSince: m.SessionSince}
	}
	st := watchdogState{backoff: m.Backoff, Session: m.Session, SessionSince: m.SessionSince, DataRestarts: m.DataRestarts}
	if m.Boot != "" && m.Boot == bootID() {

		st.nextTry = bootInstant(m.NextTry)
		st.reapplyNotBefore = bootInstant(m.ReapplyNotBefore)
		st.Degraded = m.Degraded
		st.bootID = m.Boot
	}
	return st
}

func (v *vpnApplier) saveWatchdogMemory() {
	m := watchdogMemory{
		Plan:             planFingerprint(v.watch.plan),
		Boot:             bootID(),
		Backoff:          v.watch.backoff,
		NextTry:          time.Duration(v.watch.nextTry),
		ReapplyNotBefore: time.Duration(v.watch.reapplyNotBefore),
		Degraded:         v.watch.Degraded,
		Session:          v.watch.Session,
		SessionSince:     v.watch.SessionSince,
		DataRestarts:     v.watch.DataRestarts,
	}
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := durable.MkdirAll(filepath.Dir(watchdogMemoryFile), 0o750); err != nil {
		log.Printf("vpn: watchdog memory dir: %v", err)
		return
	}

	if err := durable.Write(watchdogMemoryFile, append(data, '\n'), 0o600); err != nil {
		log.Printf("vpn: watchdog memory write: %v", err)
	}
}

func pausedForPlan(p vpnPlan) bool { return loadWatchdogMemory(p).Paused }

func (v *vpnApplier) clearPause(st *vpnState) {
	v.watchMu.Lock()
	was := v.watch.Paused
	v.watch.Paused = false
	v.watch.plan = st.Plan
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
	if !was && !pausedForPlan(st.Plan) {
		return
	}
	if drv, ok := v.driver(st).(pausable); ok {
		if err := drv.resume(); err != nil {
			log.Printf("vpn: could not resume connection attempts: %v", err)
		}
	}
}
