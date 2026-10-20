package network

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

const (
	WatchIdle       = ""
	WatchWaiting    = "waiting"
	WatchConfirmed  = "confirmed"
	WatchRolledBack = "rolledback"
)

const watchStep = time.Second

const seenWithin = 3 * watchStep

type WatchView struct {
	State   string
	Method  string
	Address bool
	Left    int
	Total   int
}

type WatchPlan struct {
	Method   string
	Window   time.Duration
	NeedSeen bool
	Probe    func() bool
	Confirm  func() error
	Cancel   func()
}

type wizardWatch struct {
	mu       sync.Mutex
	plan     WatchPlan
	state    string
	address  bool
	deadline time.Time
	seen     time.Time
	stop     chan struct{}
}

var watch wizardWatch

func StartWizardWatch(p WatchPlan) {
	watch.mu.Lock()
	if watch.stop != nil {
		close(watch.stop)
	}
	now := time.Now()
	watch.plan, watch.state, watch.address = p, WatchWaiting, false

	watch.deadline, watch.seen = now.Add(p.Window-2*watchStep), now
	stop := make(chan struct{})
	watch.stop = stop
	watch.mu.Unlock()
	go func() {
		t := time.NewTicker(watchStep)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				if !watch.tick(now, stop) {
					return
				}
			}
		}
	}()
}

func (w *wizardWatch) tick(now time.Time, stop chan struct{}) bool {
	w.mu.Lock()
	if w.stop != stop || w.state != WatchWaiting {
		w.mu.Unlock()
		return false
	}
	p := w.plan
	if !now.Before(w.deadline) {
		w.finish(WatchRolledBack)
		w.mu.Unlock()
		p.Cancel()
		return false
	}
	w.mu.Unlock()
	up := p.Probe()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop != stop || w.state != WatchWaiting {
		return false
	}
	w.address = up
	if !up || (p.NeedSeen && now.Sub(w.seen) > seenWithin) {
		return true
	}
	w.confirmLocked()
	return false
}

func (w *wizardWatch) confirmLocked() {
	if err := w.plan.Confirm(); err != nil {
		w.finish(WatchRolledBack)
		return
	}
	w.finish(WatchConfirmed)
}

func (w *wizardWatch) finish(state string) {
	w.state = state
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
}

func WizardWatch() WatchView {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	now := time.Now()
	watch.seen = now
	v := WatchView{State: watch.state, Method: watch.plan.Method, Address: watch.address,
		Total: int(watch.plan.Window / time.Second)}
	if watch.state == WatchWaiting {
		v.Left = int(watch.deadline.Sub(now).Round(time.Second) / time.Second)
		if v.Left < 0 {
			v.Left = 0
		}
	}
	if watch.state == WatchConfirmed {
		v.Address = true
	}
	return v
}

func KeepWizardChange() bool {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if watch.state != WatchWaiting {
		return false
	}
	watch.confirmLocked()
	return watch.state == WatchConfirmed
}

func ProviderUp(st *netstatus.Status, dev string) bool {
	if st == nil || dev == "" {
		return false
	}
	routed := false
	for _, r := range st.DefaultRoutes {
		if r.Dev == dev {
			routed = true
		}
	}
	if !routed {
		return false
	}
	for _, i := range st.Interfaces {
		if i.Name != dev {
			continue
		}
		for _, a := range i.Addresses {
			ip, _, err := net.ParseCIDR(a)
			if err == nil && ip.To4() != nil && !strings.HasPrefix(a, "169.254.") {
				return true
			}
		}
	}
	return false
}
