package main

import (
	"bytes"
	"log"
	"os"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

type heldState struct {
	ruleset []byte

	working bool

	plan *nftgen.FirewallPlan

	gen uint64

	forward bool
}

func (f *firewallApplier) noteLoad(ruleset []byte) {
	f.held.ruleset = append([]byte(nil), ruleset...)
	f.held.working = nftgen.IsWorking(ruleset)
	f.held.plan = nil
	f.held.gen++

	sys := f.guard.system()
	if f.guard.emergency && f.held.working && f.held.forward {
		sys.setForward(true)
	}
	if f.guard.emergency {
		f.guard.reopenedAt = sys.now()
	}
	f.guard.shape, _ = sys.shape()
	f.guard.emergency, f.guard.failed = false, false
}

func (f *firewallApplier) notePlan(plan nftgen.FirewallPlan) {
	if f.held.working {
		p := plan
		f.held.plan = &p
	}
}

func (f *firewallApplier) render(plan nftgen.FirewallPlan) ([]byte, error) {
	snap := capsOf(f.caps)
	caps := hostcaps.Caps(snap, nftgen.Options)
	ruleset := []byte(plan.Generate(caps))
	err := f.dryRun(ruleset)
	if err == nil || caps == (nftgen.Caps{}) {
		return ruleset, err
	}
	log.Printf("firewall: optional parts rejected, drawing without them: %v", err)
	if f.caps != nil {
		go f.caps.recheck(snap.Digest)
	}
	ruleset = []byte(plan.Generate(nftgen.Caps{}))
	return ruleset, f.dryRun(ruleset)
}

func (f *firewallApplier) recallPlan() {
	if f.held.plan != nil || !f.held.working || f.composer == nil {
		return
	}
	facts, ok := f.composer.FirewallFacts()
	if !ok {
		return
	}
	plan := f.composer.FirewallWith(facts)
	f.held.plan = &plan
}

func (f *firewallApplier) redraw() {
	if f.awaiting != nil && f.awaiting() {
		return
	}
	if f.composer != nil && f.composer.Sealed() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recallPlan()
	if !f.held.working || f.held.plan == nil || f.guard.emergency {
		return
	}
	if cur, err := os.ReadFile(nftFile); err != nil || !bytes.Equal(cur, f.held.ruleset) {
		return
	}
	plan := *f.held.plan
	ruleset, err := f.render(plan)
	if err != nil || bytes.Equal(ruleset, f.held.ruleset) {
		return
	}
	if _, err := f.loadAndPersist(ruleset); err != nil {
		log.Printf("firewall: redraw after passport change failed: %v", err)
		return
	}
	f.notePlan(plan)
	log.Printf("firewall: ruleset redrawn after passport change")
}
