package system

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

type fakeHost struct {
	status  hostcaps.Status
	stored  string
	reapply int
	fail    bool
	busy    bool
	audited []settings.Section
}

func (f *fakeHost) reconciler() *Reconciler {
	return &Reconciler{
		passport: func() (hostcaps.Status, error) { return f.status, nil },
		reapply: map[settings.Section]Reapply{settings.SectionDHCP: func() error {
			f.reapply++
			if f.busy {
				return ErrNotNow
			}
			if f.fail {
				return errors.New("агент отказал")
			}
			return nil
		}},
		load:  func() string { return f.stored },
		save:  func(v string) error { f.stored = v; return nil },
		audit: func(s settings.Section) { f.audited = append(f.audited, s) },
	}
}

func snapshot(retry hostcaps.Answer, cake hostcaps.Answer) hostcaps.Status {
	return hostcaps.Status{Snapshot: hostcaps.Snapshot{TakenAt: "2026-10-19T12:00:00Z", Facts: []hostcaps.Fact{
		{ID: "kea.socket_retry", Answer: retry, Consumers: []string{"dhcp"}},
		{ID: "kernel.cake", Answer: cake, Consumers: []string{"qos"}},
	}}}
}

func TestFirstSightIsRememberedWithoutReapply(t *testing.T) {
	f := &fakeHost{status: snapshot(hostcaps.No, hostcaps.Yes)}
	if redone, err := f.reconciler().Step(); err != nil || len(redone) > 0 || f.reapply != 0 {
		t.Fatalf("первая встреча не перерисовывает: %v %v %d", redone, err, f.reapply)
	}
	if f.stored == "" {
		t.Fatal("отпечаток не запомнен")
	}
}

func TestChangedFactsReapplyOnce(t *testing.T) {
	f := &fakeHost{status: snapshot(hostcaps.No, hostcaps.Yes)}
	r := f.reconciler()
	_, _ = r.Step()
	f.status = snapshot(hostcaps.Yes, hostcaps.Yes)
	if redone, _ := r.Step(); len(redone) != 1 || f.reapply != 1 || len(f.audited) != 1 {
		t.Fatalf("ждали одну перерисовку DHCP: %v, вызовов %d", redone, f.reapply)
	}
	if _, _ = r.Step(); f.reapply != 1 {
		t.Fatal("повторный шаг без изменений перерисовал снова")
	}
}

func TestForeignFactDoesNotTouchSection(t *testing.T) {
	f := &fakeHost{status: snapshot(hostcaps.No, hostcaps.Yes)}
	r := f.reconciler()
	_, _ = r.Step()
	f.status = snapshot(hostcaps.No, hostcaps.No)
	if _, _ = r.Step(); f.reapply != 0 {
		t.Fatal("смена факта очереди перерисовала DHCP")
	}
}

func TestFailedReapplyIsRetriedWithBackoff(t *testing.T) {
	f := &fakeHost{status: snapshot(hostcaps.No, hostcaps.Yes)}
	r := f.reconciler()
	_, _ = r.Step()
	f.status, f.fail = snapshot(hostcaps.Yes, hostcaps.Yes), true
	var calls []int
	for i := 0; i < 8; i++ {
		_, _ = r.Step()
		calls = append(calls, f.reapply)
	}

	if want := []int{1, 1, 2, 2, 2, 3, 3, 3}; fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("паузы между попытками: %v, ждали %v", calls, want)
	}
	f.fail = false
	for i := 0; i < 4; i++ {
		_, _ = r.Step()
	}
	if f.reapply != 4 || len(f.audited) != 1 {
		t.Fatalf("после починки раздел обязан перерисоваться: вызовов %d", f.reapply)
	}
}

func TestBusySectionIsNotAFailure(t *testing.T) {
	f := &fakeHost{status: snapshot(hostcaps.No, hostcaps.Yes)}
	r := f.reconciler()
	_, _ = r.Step()
	f.status = snapshot(hostcaps.Yes, hostcaps.Yes)
	f.busy = true
	_, _ = r.Step()
	f.busy = false
	if redone, _ := r.Step(); len(redone) != 1 || f.reapply != 2 {
		t.Fatalf("занятый раздел обязан повториться на следующем шаге: %v, вызовов %d", redone, f.reapply)
	}
}

func TestNotReadyPassportIsSkipped(t *testing.T) {
	f := &fakeHost{status: hostcaps.Status{Probing: true}}
	if _, _ = f.reconciler().Step(); f.stored != "" || f.reapply != 0 {
		t.Fatal("пока паспорт снимается, сверять не с чем")
	}
}

func TestStaleOnlyAfterTwoSteps(t *testing.T) {
	st := snapshot(hostcaps.Yes, hostcaps.Yes)
	taken, _ := time.Parse(time.RFC3339, st.TakenAt)
	applied := `{"dhcp":"` + hostcaps.SectionDigest(snapshot(hostcaps.No, hostcaps.Yes).Facts, "dhcp") + `"}`
	if got := staleSections(st, applied, taken.Add(ReconcileEvery)); len(got) != 0 {
		t.Fatalf("сверка ещё не успела — рано звать человека: %v", got)
	}
	if got := staleSections(st, applied, taken.Add(3*ReconcileEvery)); len(got) != 1 || got[0] != settings.SectionDHCP {
		t.Fatalf("раздел не перерисован дольше двух шагов: %v", got)
	}
	fresh := `{"dhcp":"` + hostcaps.SectionDigest(st.Facts, "dhcp") + `"}`
	if got := staleSections(st, fresh, taken.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("перерисованный раздел назван отставшим: %v", got)
	}
}

func TestOnlyGuardNoBlocks(t *testing.T) {
	facts := []hostcaps.Fact{
		{ID: "a", Class: hostcaps.ClassGuard, Answer: hostcaps.No, Consumers: []string{"network"}, Missing: "Нет А."},
		{ID: "b", Class: hostcaps.ClassGuard, Answer: hostcaps.Unknown, Consumers: []string{"network"}},
		{ID: "c", Class: hostcaps.ClassFeature, Answer: hostcaps.No, Consumers: []string{"network"}},
		{ID: "d", Class: hostcaps.ClassGuard, Answer: hostcaps.No, Consumers: []string{"vpn"}},
	}
	b := Blocking(facts, "network")
	if len(b) != 1 || b[0].ID != "a" {
		t.Fatalf("блокирует только защитное «нет» своего раздела: %v", b)
	}
	if txt := RefusalText(b, "network"); txt != "Раздел «Сеть» применить нельзя. Нет А." {
		t.Fatalf("текст отказа: %q", txt)
	}
}
