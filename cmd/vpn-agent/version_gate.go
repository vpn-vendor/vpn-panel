package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

type versionGate struct {
	mu        sync.Mutex
	ceiling   func() string
	installed func() string
	held      func() bool
	hold      func() error
	unhold    func() error
	cmp       func(a, op, b string) bool

	rolledBackFrom func() string
}

func (g *versionGate) onPolicyChange() {
	g.mu.Lock()
	defer g.mu.Unlock()
	ceil := g.ceiling()
	if ceil == "" {
		return
	}
	inst := g.installed()
	if inst == "" {
		return
	}

	freeze := g.cmp(inst, "ge", ceil)
	if g.rolledBackFrom != nil {
		if from := g.rolledBackFrom(); from != "" && !g.cmp(ceil, "gt", from) {
			freeze = true
		}
	}
	switch {
	case freeze && !g.held():
		if err := g.hold(); err != nil {
			log.Printf("version-gate: hold: %v", err)
		}
	case !freeze && g.held():
		if err := g.unhold(); err != nil {
			log.Printf("version-gate: unhold: %v", err)
		}
	}
}

func dpkgCompare(a, op, b string) bool {
	bin, err := findBinary(dpkgCandidates)
	if err != nil {
		return false
	}
	return exec.Command(bin, "--compare-versions", a, op, b).Run() == nil //nolint:gosec
}

func aptMarkUnhold(pkg string) error {
	bin, err := findBinary(aptMarkCandidates)
	if err != nil {
		return err
	}
	out, cerr := exec.Command(bin, "unhold", pkg).CombinedOutput() //nolint:gosec
	if cerr != nil {
		return fmt.Errorf("%s: %s", cerr, firstLine(out))
	}
	return nil
}

func aptHeld() bool {
	out, err := exec.Command("dpkg-query", "-W", "-f=${db:Status-Want}", "vpn-panel").Output()
	return err == nil && strings.TrimSpace(string(out)) == "hold"
}
