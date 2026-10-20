package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	codeNetBusy     = 1001
	codeNetPlan     = 1002
	codeNetAwaiting = 1003
	codeNetConfig   = 1004
	codeNetNoWindow = 1005
	codeNetFwPlan   = 1006
	codeNetFwRules  = 1007
	codeNetFwApply  = 1008
	codeNetTakeover = 1009
	codeNetTakeBusy = 1010
)

const confirmBudget = 10 * time.Second

const netplanFile = "/etc/netplan/99-vpn-panel.yaml"

const netplanBackup = "/etc/netplan/.99-vpn-panel.yaml.prev"

const netplanTryMark = "/run/netplan/netplan-try.ready"

const backupAbsentMarker = "\x00absent\x00"

type netplanApplier struct {
	mu       sync.Mutex
	limiter  *ratelimit.Limiter
	firewall *firewallApplier

	tryCmd    *exec.Cmd
	tryStdin  io.WriteCloser
	tryOutput *bytes.Buffer
	tryDone   chan struct{}

	surround  *surroundings
	confirmed bool

	aborted  bool
	planHash string

	nmProfiles []string

	fwRuleset  []byte
	fwPlan     nftgen.FirewallPlan
	fwPrev     []byte
	fwPrevSeen bool

	pppoePrevEnabled bool

	pppoeTouched bool

	pendingFacts *nftgen.FirewallPlan

	onPathChanged func()

	linkLocal *linkLocalHelper

	takeover *takeoverRunner

	caps hostCapsSource
}

func planCards(p netplangen.Plan) []string {
	out := make([]string, 0, len(p.Interfaces))
	for _, i := range p.Interfaces {
		out = append(out, i.Name)
	}
	return out
}

func (a *netplanApplier) takeoverUndo() {
	if a.takeover == nil {
		return
	}
	if err := a.takeover.restoreAside(); err != nil {
		log.Printf("takeover: aside files not restored: %v", err)
	}
	a.takeover.undoUnits()
}

func (a *netplanApplier) takeoverConfirmed() {
	if a.takeover == nil {
		return
	}
	if err := a.takeover.confirm(); err != nil {
		log.Printf("takeover: confirm: %v", err)
	}
}

func (a *netplanApplier) takeoverFinish() {
	if a.takeover == nil {
		return
	}
	a.takeover.sys.spawn(a.takeover.finishLogged)
}

func newNetplanApplier(firewall *firewallApplier) *netplanApplier {

	return &netplanApplier{limiter: ratelimit.New(3, 1, 30*time.Second), firewall: firewall}
}

func (a *netplanApplier) recoverAfterCrash() {

	if err := os.Remove(netplanTryMark); err == nil {
		log.Printf("netplan: stale confirmation mark removed")
	}
	found, restored := a.restoreBackup()
	if found && !restored {
		return
	}
	if !found {

		clearPPPoEBackups()
		return
	}
	hadPPPoE := pppoeBackupsLeft()
	restorePPPoEFiles()

	if netplanBin, err := findBinary([]string{"/usr/sbin/netplan", "/sbin/netplan"}); err == nil {
		if out, err := exec.Command(netplanBin, "apply").CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("netplan: previous network not re-applied: %s", firstLine(out))
		}
	}
	if hadPPPoE {

		if _, err := os.Stat(pppoePeerPath); err == nil {
			if err := pppoeStart(); err != nil {
				log.Printf("pppoe: previous link not restored: %v", err)
			}
		} else {
			pppoeStop()
		}
	}
	log.Printf("netplan: unconfirmed apply rolled back after interruption")
}

func findBinary(candidates []string) (string, error) {

	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("binary not found in %v", candidates)
}

func currentDefinitionIDs() map[string]string {
	netplanBin, err := findBinary([]string{"/usr/sbin/netplan", "/sbin/netplan"})
	if err != nil {
		return nil
	}
	out, err := exec.Command(netplanBin, "status", "--format=json").Output() //nolint:gosec
	if err != nil {
		log.Printf("netplan: status unavailable, definitions by interface name")
		return nil
	}
	return netplangen.ParseStatusIDs(out)
}

func detectRenderer() string {
	nmcli, err := findBinary([]string{"/usr/bin/nmcli", "/bin/nmcli"})
	if err != nil {
		return netplangen.RendererNetworkd
	}
	out, err := exec.Command(nmcli, "-t", "-f", "RUNNING", "general").Output() //nolint:gosec
	if err == nil && string(out) == "running\n" {
		return netplangen.RendererNM
	}
	return netplangen.RendererNetworkd
}

type applyParams struct {
	Plan       netplangen.Plan      `json:"plan"`
	Guard      bool                 `json:"guard"`
	TimeoutSec int                  `json:"timeout_sec"`
	Firewall   *nftgen.FirewallPlan `json:"firewall,omitempty"`

	PPPoEPassword string `json:"pppoe_password,omitempty"`

	Takeover *takeoverConsent `json:"takeover,omitempty"`

	PPPoEPasswordSource string `json:"pppoe_password_source,omitempty"`
}

func (a *netplanApplier) networkApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p applyParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку", Data: map[string]any{"recoverable": false}}
	}
	if !a.limiter.Allow("apply") {
		return nil, agentrpc.Busy(codeNetBusy, "слишком частые применения настроек сети — подождите", a.limiter.RetryIn("apply"))
	}

	status, err := netstatus.Collect()
	if err != nil {
		return nil, internalErr(errReadInterfaces, true)
	}
	knownNames := map[string]bool{}
	for _, i := range status.Interfaces {
		if !i.Loopback {
			knownNames[i.Name] = true
		}
	}
	if err := p.Plan.Validate(knownNames); err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeNetPlan, Message: err.Error(),
			Data: map[string]any{"recoverable": false}}
	}

	sel, rerr := p.Takeover.resolve(a.takeover, planLANs(p.Plan), planCards(p.Plan))
	if rerr != nil {
		return nil, rerr
	}
	grabbing := len(sel.Items) > 0

	var ruleset []byte
	var fwFacts *nftgen.FirewallPlan
	var fwPlan nftgen.FirewallPlan
	if p.Firewall != nil {
		if rerr := a.firewall.sealedErr(); rerr != nil {
			return nil, rerr
		}
		facts := *p.Firewall
		plan := facts
		if a.firewall.composer != nil {
			plan = a.firewall.composer.FirewallWith(facts)
		}
		if rerr := validateFirewallPlan(&plan, p.Plan.EffectiveWANs()...); rerr != nil {
			return nil, &agentrpc.ErrorObject{Code: codeNetFwPlan, Message: "защита: " + rerr.Message,
				Data: map[string]any{"recoverable": false}}
		}
		fwFacts, fwPlan = &facts, plan
		var err error
		if ruleset, err = a.firewall.render(plan); err != nil {
			return nil, &agentrpc.ErrorObject{Code: codeNetFwRules,
				Message: "правила защиты не прошли проверку: " + err.Error(),
				Data:    map[string]any{"recoverable": false}}
		}
	}

	renderer := detectRenderer()
	defIDs := currentDefinitionIDs()
	yaml := p.Plan.Generate(renderer, defIDs)
	hash := hashBytes(yaml)

	if cur, err := os.ReadFile(netplanFile); err != nil || string(cur) != string(yaml) {
		if rerr := a.surround.applyGuard(planLANs(p.Plan), sel.Doomed()...); rerr != nil {
			return nil, rerr
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.pppoeTouched = false
	a.nmProfiles = nil
	if renderer == netplangen.RendererNM {
		for _, id := range p.Plan.DefinitionIDs(defIDs) {
			a.nmProfiles = append(a.nmProfiles, netplangen.NMConnectionName(id))
		}
	}
	if a.tryDone != nil {
		return nil, &agentrpc.ErrorObject{Code: codeNetAwaiting,
			Message: "предыдущее применение ещё ожидает подтверждения",
			Data:    map[string]any{"recoverable": true}}
	}

	if grabbing && !p.Guard {
		return nil, takeoverNoWindowErr()
	}

	if cur, err := os.ReadFile(netplanFile); err == nil && string(cur) == string(yaml) {
		if grabbing {
			return nil, takeoverNoWindowErr()
		}
		if perr := a.bringUpEffectiveWAN(p); perr != nil {
			a.tearDownEffectiveWAN()
			return nil, perr
		}
		clearPPPoEBackups()
		fwChanged, ferr := a.applyFirewallDirect(ruleset, fwPlan)
		if ferr != nil {
			return nil, ferr
		}
		a.commitFacts(fwFacts)
		return map[string]any{"changed": fwChanged, "state": "applied", "hash": hash}, nil
	}

	if a.linkLocal != nil {
		a.linkLocal.remove()
	}
	if err := a.writeWithBackup(yaml); err != nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}

	if grabbing {
		if _, err := a.takeover.begin(sel.Plan); err != nil {
			a.restoreBackup()
			return nil, takeoverBusyErr(err)
		}
	}

	netplanBin, err := findBinary([]string{"/usr/sbin/netplan", "/sbin/netplan"})
	if err != nil {
		a.takeoverUndo()
		a.restoreBackup()
		return nil, internalErr(errToolMissing, false)
	}

	if out, err := dryRunGenerate(netplanBin); err != nil {
		a.takeoverUndo()
		a.restoreBackup()
		return nil, &agentrpc.ErrorObject{Code: codeNetConfig,
			Message: "конфигурация не прошла проверку: " + firstLine(out),
			Data:    map[string]any{"recoverable": false}}
	}

	if !p.Guard {

		if out, err := exec.Command(netplanBin, "apply").CombinedOutput(); err != nil { //nolint:gosec
			a.restoreBackup()
			return nil, detailErr("не удалось применить настройки сети — попробуйте ещё раз; если повторяется, обратитесь в поддержку", string(out), true)
		}

		if perr := a.bringUpEffectiveWAN(p); perr != nil {
			a.tearDownEffectiveWAN()
			a.restoreBackup()
			_, _ = exec.Command(netplanBin, "apply").CombinedOutput() //nolint:gosec
			return nil, perr
		}
		a.finishApplied(hash)
		clearPPPoEBackups()
		if _, ferr := a.applyFirewallDirect(ruleset, fwPlan); ferr != nil {

			return nil, ferr
		}
		a.commitFacts(fwFacts)
		return map[string]any{"changed": true, "state": "applied", "hash": hash}, nil
	}

	timeout := p.TimeoutSec
	if timeout < 15 || timeout > 900 {
		timeout = 120
	}
	cmd := exec.Command(netplanBin, "try", "--timeout", fmt.Sprint(timeout)) //nolint:gosec

	output := &limitedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = output, output
	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.takeoverUndo()
		a.restoreBackup()
		return nil, detailErr("не удалось запустить проверку связи — попробуйте ещё раз", err.Error(), true)
	}
	if err := cmd.Start(); err != nil {
		a.takeoverUndo()
		a.restoreBackup()
		return nil, detailErr("не удалось запустить проверку связи — попробуйте ещё раз", err.Error(), true)
	}
	a.tryCmd, a.tryStdin, a.confirmed, a.aborted, a.planHash = cmd, stdin, false, false, hash
	a.pendingFacts = fwFacts
	a.tryOutput = &output.buf
	a.tryDone = make(chan struct{})
	log.Printf("netplan: try started (timeout %d s, firewall %v)", timeout, ruleset != nil)

	a.fwRuleset, a.fwPrev, a.fwPrevSeen = nil, nil, false
	if ruleset != nil {
		a.firewall.mu.Lock()
		a.fwPrev, a.fwPrevSeen = a.firewall.snapshot()
		err := a.firewall.load(ruleset)
		if err == nil {
			a.firewall.notePlan(fwPlan)
		}
		a.firewall.mu.Unlock()
		if err != nil {

			a.confirmed, a.aborted = true, true
			_, _ = io.WriteString(a.tryStdin, "\n")
			go a.watchTry(cmd)
			return nil, &agentrpc.ErrorObject{Code: codeNetFwApply,
				Message: "защита не применилась, сеть откачена: " + err.Error(),
				Data:    map[string]any{"recoverable": true}}
		}
		a.fwRuleset, a.fwPlan = ruleset, fwPlan
	}

	if perr := a.bringUpEffectiveWAN(p); perr != nil {
		a.tearDownEffectiveWAN()

		a.confirmed, a.aborted = true, true
		_, _ = io.WriteString(a.tryStdin, "\n")
		go a.watchTry(cmd)
		return nil, perr
	}

	go a.watchTry(cmd)

	return map[string]any{"changed": true, "state": "awaiting_confirm",
		"hash": hash, "timeout_sec": timeout}, nil
}

func (a *netplanApplier) watchTry(cmd *exec.Cmd) {
	waitErr := cmd.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.confirmed {

		tail := ""
		if a.tryOutput != nil {
			tail = lastLines(a.tryOutput.String(), 3)
		}
		log.Printf("netplan: try ended without confirmation (exit: %v): %s", waitErr, tail)
	}
	confirmed := false
	if a.aborted {

		a.tearDownEffectiveWAN()
		a.takeoverUndo()
		a.restoreBackup()
		if netplanBin, err := findBinary([]string{"/usr/sbin/netplan", "/sbin/netplan"}); err == nil {
			_, _ = exec.Command(netplanBin, "apply").CombinedOutput() //nolint:gosec
		}
		if a.fwRuleset != nil {
			a.firewall.mu.Lock()
			a.firewall.rollback(a.fwPrev, a.fwPrevSeen)
			a.firewall.mu.Unlock()
		}
		log.Printf("netplan: bring-up failed, previous network restored")
	} else if a.confirmed {
		confirmed = true
		a.takeoverConfirmed()
		a.finishApplied(a.planHash)
		if a.fwRuleset != nil {

			a.firewall.mu.Lock()
			if _, err := a.firewall.loadAndPersist(a.fwRuleset); err != nil {
				log.Printf("firewall: persist after confirm failed: %v", err)
			} else {
				a.firewall.notePlan(a.fwPlan)
				a.firewall.captureUFW()
			}
			a.firewall.mu.Unlock()
		}
		clearPPPoEBackups()
		a.commitFacts(a.pendingFacts)
		log.Printf("netplan: configuration confirmed")
	} else {
		a.takeoverUndo()
		a.restoreBackup()

		a.tearDownEffectiveWAN()
		if a.fwRuleset != nil {
			a.firewall.mu.Lock()
			a.firewall.rollback(a.fwPrev, a.fwPrevSeen)
			a.firewall.mu.Unlock()
		}
		log.Printf("netplan: configuration rolled back")
	}
	a.fwRuleset, a.fwPrev, a.fwPrevSeen, a.aborted, a.pendingFacts = nil, nil, false, false, nil
	close(a.tryDone)
	a.tryCmd, a.tryStdin, a.tryDone, a.tryOutput = nil, nil, nil, nil
	if confirmed {

		a.takeoverFinish()
	}
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf.Write(p)
	}
	return n, nil
}

func lastLines(text string, n int) string {
	text = strings.ReplaceAll(text, "\r", "\n")
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (a *netplanApplier) applyFirewallDirect(ruleset []byte, plan nftgen.FirewallPlan) (bool, *agentrpc.ErrorObject) {
	if ruleset == nil {
		return false, nil
	}
	a.firewall.mu.Lock()
	defer a.firewall.mu.Unlock()
	changed, err := a.firewall.loadAndPersist(ruleset)
	if err != nil {
		return false, &agentrpc.ErrorObject{Code: codeNetFwApply,
			Message: "защита не применилась: " + err.Error(),
			Data:    map[string]any{"recoverable": true}}
	}
	a.firewall.notePlan(plan)
	a.firewall.captureUFW()
	return changed, nil
}

func (a *netplanApplier) awaitingConfirm() bool {
	if !a.mu.TryLock() {
		return true
	}
	defer a.mu.Unlock()
	return a.tryDone != nil
}

func (a *netplanApplier) networkPending(json.RawMessage) (any, *agentrpc.ErrorObject) {
	a.mu.Lock()
	awaiting := a.tryDone != nil
	a.mu.Unlock()
	hash := ""
	if cur, err := os.ReadFile(netplanFile); err == nil {
		hash = hashBytes(cur)
	}
	return map[string]any{"awaiting": awaiting, "hash": hash}, nil
}

func (a *netplanApplier) networkConfirm(json.RawMessage) (any, *agentrpc.ErrorObject) {
	a.mu.Lock()
	if a.tryDone == nil {
		a.mu.Unlock()
		return nil, &agentrpc.ErrorObject{Code: codeNetNoWindow,
			Message: "нет применения, ожидающего подтверждения",
			Data:    map[string]any{"recoverable": false}}
	}
	a.confirmed = true
	_, _ = io.WriteString(a.tryStdin, "\n")
	done := a.tryDone
	a.mu.Unlock()

	select {
	case <-done:
	case <-time.After(confirmBudget):
		return nil, internalErr("подтверждение не завершилось вовремя — обновите страницу и проверьте состояние сети", true)
	}
	return map[string]any{"state": "applied"}, nil
}

func (a *netplanApplier) networkCancel(json.RawMessage) (any, *agentrpc.ErrorObject) {
	a.mu.Lock()
	if a.tryDone == nil {
		a.mu.Unlock()
		return map[string]any{"state": "idle"}, nil
	}
	a.confirmed, a.aborted = true, true
	_, _ = io.WriteString(a.tryStdin, "\n")
	done := a.tryDone
	a.mu.Unlock()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		return nil, internalErr("откат не завершился вовремя — обновите страницу и проверьте состояние сети", true)
	}
	return map[string]any{"state": "rolled_back"}, nil
}

func dryRunGenerate(netplanBin string) ([]byte, error) {
	root, err := os.MkdirTemp("", "vpn-panel-netplan-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	dst := filepath.Join(root, "etc", "netplan")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Dir(netplanFile))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := filepath.Base(e.Name())
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, ".") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(filepath.Dir(netplanFile), name)) //nolint:gosec
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o600); err != nil { //nolint:gosec
			return nil, err
		}
	}
	return exec.Command(netplanBin, "generate", "--root-dir", root).CombinedOutput() //nolint:gosec
}

func (a *netplanApplier) writeWithBackup(yaml []byte) error {
	prev := []byte(backupAbsentMarker)
	if cur, err := os.ReadFile(netplanFile); err == nil {
		prev = cur
	}

	if err := durable.Write(netplanBackup, prev, 0o600); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if err := durable.Write(netplanFile, yaml, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func (a *netplanApplier) restoreBackup() (found, restored bool) {
	data, err := os.ReadFile(netplanBackup)
	if err != nil {
		return false, false
	}
	if string(data) == backupAbsentMarker {
		err = durable.Remove(netplanFile)
	} else {
		err = durable.Write(netplanFile, data, 0o600)
	}
	if err != nil {
		log.Printf("netplan: previous plan not restored: %v", err)
		return true, false
	}
	if err := durable.Remove(netplanBackup); err != nil {
		log.Printf("netplan: backup not removed: %v", err)
	}
	return true, true
}

func activateNMProfiles(names []string) {
	if len(names) == 0 {
		return
	}
	nmcli, err := findBinary([]string{"/usr/bin/nmcli", "/bin/nmcli"})
	if err != nil {
		return
	}
	activeOut, _ := exec.Command(nmcli, "-t", "-f", "NAME", "connection", "show", "--active").Output() //nolint:gosec
	active := map[string]bool{}
	for _, line := range strings.Split(string(activeOut), "\n") {
		active[strings.TrimSpace(line)] = true
	}
	for _, name := range names {
		if active[name] {
			continue
		}

		if out, err := exec.Command(nmcli, "-w", "20", "connection", "up", name).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("netplan: nm profile %s not activated: %s", name, firstLine(out))
			continue
		}
		log.Printf("netplan: nm profile %s activated", name)
	}
}

func (a *netplanApplier) commitFacts(facts *nftgen.FirewallPlan) {
	if facts == nil || a.firewall.composer == nil {
		return
	}
	prev := a.firewall.composer.FirewallWANs()
	a.firewall.composer.SetFirewallFacts(*facts)
	if prev != nil && !sameNames(prev, facts.WANs) && a.onPathChanged != nil {
		log.Printf("netplan: provider path changed %v -> %v", prev, facts.WANs)
		go a.onPathChanged()
	}
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
}

func (a *netplanApplier) finishApplied(hash string) {
	activateNMProfiles(a.nmProfiles)

	if err := durable.Remove(netplanBackup); err != nil {
		log.Printf("netplan: backup not removed: %v", err)
	}
	_ = hash
}

func internalErr(msg string, recoverable bool) *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: agentrpc.CodeInternalError,
		Message: msg, Data: map[string]any{"recoverable": recoverable}}
}

func detailErr(msg, detail string, recoverable bool) *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: agentrpc.CodeInternalError, Message: msg,
		Data: map[string]any{"recoverable": recoverable, "detail": firstLine([]byte(detail))}}
}

const (
	errReadInterfaces = "не удалось прочитать состояние сети — обновите страницу; если повторяется, обратитесь в поддержку"
	errToolMissing    = "в системе не найден нужный инструмент — обратитесь в поддержку"
	errWriteConfig    = "не удалось сохранить настройки на сервере — проверьте свободное место на диске или обратитесь в поддержку"
)

func firstLine(b []byte) string {
	s := string(b)
	if i := len(s); i > 200 {
		s = s[:200]
	}
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

func hashBytes(b []byte) string {
	var h uint64 = 1469598103934665603
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}
