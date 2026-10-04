package listen

import (
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/bindset"
	"github.com/vpn-vendor/vpn-panel-core/internal/multilisten"
)

type AppliedLANs func() []string

type Manager struct {
	https    *multilisten.Listener
	redirect *multilisten.Listener
	dev      bool
	applied  AppliedLANs
	logf     func(string, ...any)

	mu           sync.Mutex
	pending      []string
	pendingUntil time.Time
	last         bindset.Set
}

var (
	globalMu sync.RWMutex
	global   *Manager
)

func Init(https, redirect *multilisten.Listener, dev bool, applied AppliedLANs, logf func(string, ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	m := &Manager{https: https, redirect: redirect, dev: dev, applied: applied, logf: logf}
	globalMu.Lock()
	global = m
	globalMu.Unlock()
	m.Refresh()
	go m.loop()
	return m
}

func Current() *Manager {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

func (m *Manager) loop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		m.Refresh()
	}
}

func (m *Manager) desired() bindset.Set {
	m.mu.Lock()
	lans := m.pending
	if lans != nil && time.Now().After(m.pendingUntil) {
		m.pending, m.pendingUntil = nil, time.Time{}
		lans = nil
		m.logf("listener: confirmation window expired, back to applied roles")
	}
	m.mu.Unlock()
	if lans == nil && m.applied != nil {
		lans = m.applied()
	}
	return bindset.Compute(m.dev, lans, bindset.LocalInterfaces())
}

func (m *Manager) Refresh() {
	set := m.desired()
	ips := set.IPs()
	for _, l := range []*multilisten.Listener{m.https, m.redirect} {
		if l == nil {
			continue
		}
		if err := l.Rebind(ips); err != nil {
			m.logf("listener: bind pending (%s): %v", set.Mode, err)
		}
	}
	m.mu.Lock()
	changed := !sameSet(m.last, set)
	m.last = set
	m.mu.Unlock()
	if changed {
		m.logf("listener: mode=%s addresses=%s", set.Mode, strings.Join(ips, ","))
	}
}

func (m *Manager) SetPending(lanCIDRs []string, ttl time.Duration) {
	m.mu.Lock()
	m.pending = append([]string(nil), lanCIDRs...)
	m.pendingUntil = time.Now().Add(ttl)
	m.mu.Unlock()
	m.Refresh()
}

func (m *Manager) ClearPending() {
	m.mu.Lock()
	m.pending, m.pendingUntil = nil, time.Time{}
	m.mu.Unlock()
	m.Refresh()
}

type View struct {
	Mode    bindset.Mode
	Addrs   []bindset.Addr
	Bound   []string
	Pending bool
}

func (m *Manager) Snapshot() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := View{Mode: m.last.Mode, Addrs: m.last.Addrs, Pending: m.pending != nil}
	if m.https != nil {
		v.Bound = m.https.Bound()
	}
	return v
}

func sameSet(a, b bindset.Set) bool {
	if a.Mode != b.Mode || len(a.Addrs) != len(b.Addrs) {
		return false
	}
	for i := range a.Addrs {
		if a.Addrs[i] != b.Addrs[i] {
			return false
		}
	}
	return true
}
