package main

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/policy"
)

func geCmp(a, op, b string) bool { return a >= b }

func mkGate(ceil, inst string, held bool) (*versionGate, *[]string) {
	h := held
	var acts []string
	g := &versionGate{
		ceiling:   func() string { return ceil },
		installed: func() string { return inst },
		held:      func() bool { return h },
		hold:      func() error { h = true; acts = append(acts, "hold"); return nil },
		unhold:    func() error { h = false; acts = append(acts, "unhold"); return nil },
		cmp:       geCmp,
	}
	return g, &acts
}

func TestGateFreezesAtCeiling(t *testing.T) {
	g, acts := mkGate("0.3.3", "0.3.3", false)
	g.onPolicyChange()
	if len(*acts) != 1 || (*acts)[0] != "hold" {
		t.Fatalf("на потолке без удержания ждём hold: %v", *acts)
	}
}

func TestGateIdempotentWhenHeld(t *testing.T) {
	g, acts := mkGate("0.3.3", "0.3.3", true)
	g.onPolicyChange()
	if len(*acts) != 0 {
		t.Fatalf("повторных действий быть не должно: %v", *acts)
	}
}

func TestGateUnfreezesBelowCeiling(t *testing.T) {
	g, acts := mkGate("0.3.4", "0.3.3", true)
	g.onPolicyChange()
	if len(*acts) != 1 || (*acts)[0] != "unhold" {
		t.Fatalf("ниже потолка под удержанием ждём unhold: %v", *acts)
	}
}

func TestGateNoCeilingNoAction(t *testing.T) {
	g, acts := mkGate("", "0.3.3", true)
	g.onPolicyChange()
	if len(*acts) != 0 {
		t.Fatalf("без потолка действий быть не должно: %v", *acts)
	}
}

func mustPolicy(t *testing.T, js string) policy.Policy {
	t.Helper()
	p, _, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersionAllowedRejectsKnownBad(t *testing.T) {
	pol := mustPolicy(t, `{"schema":1,"known_bad":["0.3.3"]}`)
	if versionAllowed("0.3.3", pol, geCmp) {
		t.Fatal("плохая версия не должна быть целью отката")
	}
}

func TestVersionAllowedRejectsBelowFloor(t *testing.T) {
	pol := mustPolicy(t, `{"schema":1,"floor":"0.3.2"}`)
	if versionAllowed("0.3.1", pol, geCmp) {
		t.Fatal("версия ниже пола не должна быть целью отката")
	}
	if !versionAllowed("0.3.2", pol, geCmp) {
		t.Fatal("версия на уровне пола допустима")
	}
}

func TestVersionAllowedOK(t *testing.T) {
	pol := mustPolicy(t, `{"schema":1}`)
	if !versionAllowed("0.3.5", pol, geCmp) {
		t.Fatal("обычная версия должна быть допустима")
	}
}
