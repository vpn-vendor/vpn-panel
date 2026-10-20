package network

import (
	"errors"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func TestProviderUp(t *testing.T) {
	st := &netstatus.Status{
		Interfaces:    []netstatus.Interface{{Name: "ens2", Addresses: []string{"10.20.0.7/24"}}, {Name: "ens3", Addresses: []string{"169.254.1.2/16"}}},
		DefaultRoutes: []netstatus.Route{{Dev: "ens2", Via: "10.20.0.1"}},
	}
	if !ProviderUp(st, "ens2") {
		t.Error("адрес и маршрут через карту — провайдер ответил")
	}
	if ProviderUp(st, "ens3") {
		t.Error("без маршрута и с одним 169.254 — не ответил")
	}
	st.DefaultRoutes = append(st.DefaultRoutes, netstatus.Route{Dev: "ens3"})
	if ProviderUp(st, "ens3") {
		t.Error("169.254 — адрес, который система ставит себе сама")
	}
	if ProviderUp(nil, "ens2") || ProviderUp(st, "") {
		t.Error("без статуса или карты судить не о чем")
	}
}

type fakeAgent struct {
	up        bool
	confirmed int
	cancelled int
	fail      bool
}

func (a *fakeAgent) plan(needSeen bool) WatchPlan {
	return WatchPlan{Method: "dhcp", Window: time.Minute, NeedSeen: needSeen,
		Probe: func() bool { return a.up },
		Confirm: func() error {
			a.confirmed++
			if a.fail {
				return errors.New("служба отказала")
			}
			return nil
		},
		Cancel: func() { a.cancelled++ }}
}

func newWatch(p WatchPlan, now time.Time) (*wizardWatch, chan struct{}) {
	stop := make(chan struct{})
	return &wizardWatch{plan: p, state: WatchWaiting, deadline: now.Add(p.Window), seen: now, stop: stop}, stop
}

func TestWatchConfirmsWhenProviderAnswers(t *testing.T) {
	a := &fakeAgent{}
	now := time.Now()
	w, stop := newWatch(a.plan(false), now)
	if !w.tick(now.Add(time.Second), stop) || a.confirmed != 0 {
		t.Fatal("адреса нет — ждём, не закрепляем")
	}
	a.up = true
	if w.tick(now.Add(2*time.Second), stop) {
		t.Fatal("адрес пришёл — наблюдение окончено")
	}
	if a.confirmed != 1 || w.state != WatchConfirmed || a.cancelled != 0 {
		t.Errorf("закреплено %d, состояние %q, откатов %d", a.confirmed, w.state, a.cancelled)
	}
}

func TestWatchRollsBackOnDeadline(t *testing.T) {
	a := &fakeAgent{}
	now := time.Now()
	w, stop := newWatch(a.plan(false), now)
	if w.tick(now.Add(time.Minute), stop) {
		t.Fatal("окно истекло — наблюдение окончено")
	}
	if a.cancelled != 1 || a.confirmed != 0 || w.state != WatchRolledBack {
		t.Errorf("откатов %d, закреплено %d, состояние %q", a.cancelled, a.confirmed, w.state)
	}
}

func TestWatchRefusalMeansRollback(t *testing.T) {
	a := &fakeAgent{up: true, fail: true}
	now := time.Now()
	w, stop := newWatch(a.plan(false), now)
	w.tick(now.Add(time.Second), stop)
	if w.state != WatchRolledBack {
		t.Errorf("служба не закрепила — состояние %q, ждали откат", w.state)
	}
}

func TestWatchWaitsForAdminWhenPathChanges(t *testing.T) {
	a := &fakeAgent{up: true}
	now := time.Now()
	w, stop := newWatch(a.plan(true), now)
	if !w.tick(now.Add(seenWithin+time.Second), stop) || a.confirmed != 0 {
		t.Fatal("администратор пропал — закреплять нельзя")
	}
	w.seen = now.Add(seenWithin + time.Second)
	w.tick(now.Add(seenWithin+2*time.Second), stop)
	if a.confirmed != 1 {
		t.Error("администратор на связи и адрес есть — закрепить")
	}
}

func TestKeepConfirmsOnlyWhileWaiting(t *testing.T) {
	a := &fakeAgent{}
	now := time.Now()
	w, _ := newWatch(a.plan(false), now)
	watch.mu.Lock()
	watch.plan, watch.state, watch.stop = w.plan, w.state, w.stop
	watch.mu.Unlock()
	if !KeepWizardChange() || a.confirmed != 1 {
		t.Fatal("«Оставить всё равно» закрепляет")
	}
	if KeepWizardChange() || a.confirmed != 1 {
		t.Error("второй раз закреплять нечего")
	}
}
