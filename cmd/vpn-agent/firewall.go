package main

import (
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

const (
	codeFwPlan   = 1102
	codeFwRules  = 1104
	codeFwSealed = 1105
)

const (
	nftFile    = "/etc/nftables.d/vpn-panel.nft"
	sysctlFile = "/etc/sysctl.d/99-vpn-panel.conf"

	lockdownFile = "/etc/vpn-panel/lockdown.nft"

	lockdownStatic = "/usr/share/vpn-panel/lockdown.nft"
)

const voipUDPStreamTimeout = 300

var sysctlContent = "net.netfilter.nf_conntrack_udp_timeout_stream=" + strconv.Itoa(voipUDPStreamTimeout) + "\n"

type firewallApplier struct {
	mu sync.Mutex

	lockdownMu sync.Mutex

	composer *modeComposer

	intentBroken func() bool
}

func newFirewallApplier() *firewallApplier { return &firewallApplier{} }

var nftCandidates = []string{"/usr/sbin/nft", "/sbin/nft"}

func (f *firewallApplier) restoreOnStart() {
	data, err := os.ReadFile(nftFile)
	if err != nil {
		return
	}
	nft, err := findBinary(nftCandidates)
	if err != nil {
		log.Printf("firewall: nft not found, ruleset not restored")
		return
	}
	if out, err := runStdin(nft, data, "-f", "-"); err != nil {
		log.Printf("firewall: restore failed: %s", firstLine(out))
		return
	}
	f.applySysctl()
	log.Printf("firewall: ruleset restored")
}

func (f *firewallApplier) writeLockdown(plan nftgen.FirewallPlan) {
	f.lockdownMu.Lock()
	defer f.lockdownMu.Unlock()
	data := plan.Lockdown()
	if data == nil {
		if _, err := os.Stat(lockdownFile); err != nil {
			return
		}
		if err := durable.Remove(lockdownFile); err != nil {
			log.Printf("firewall: lockdown not removed: %v", err)
			return
		}
		log.Printf("firewall: lockdown removed (no LAN)")
		return
	}
	if cur, err := os.ReadFile(lockdownFile); err == nil && string(cur) == string(data) {
		return
	}
	if err := f.dryRun(data); err != nil {
		log.Printf("firewall: lockdown not saved, check failed: %v", err)
		return
	}
	if err := durable.MkdirAll(filepath.Dir(lockdownFile), 0o755); err != nil {
		log.Printf("firewall: lockdown not saved: %v", err)
		return
	}
	if err := durable.Write(lockdownFile, data, 0o600); err != nil {
		log.Printf("firewall: lockdown not saved: %v", err)
		return
	}
	log.Printf("firewall: lockdown saved")
}

func (f *firewallApplier) leakDrops() int64 {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return 0
	}
	out, err := exec.Command(nft, "-j", "list", "chain", "inet", "vpn_panel", "output").Output() //nolint:gosec
	if err != nil {
		return 0
	}
	return parseLeakDrops(out)
}

func (f *firewallApplier) echoCounters() (out, in int64, ok bool) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return 0, 0, false
	}
	o, err := exec.Command(nft, "-j", "list", "chain", "inet", "vpn_panel", "output").Output() //nolint:gosec
	if err != nil {
		return 0, 0, false
	}
	i, err := exec.Command(nft, "-j", "list", "chain", "inet", "vpn_panel", "input").Output() //nolint:gosec
	if err != nil {
		return 0, 0, false
	}
	return parseCounter(o, nftgen.EchoOutComment), parseCounter(i, nftgen.EchoInComment), true
}

func (f *firewallApplier) leakWatch() (int64, bool) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return 0, false
	}
	out, err := exec.Command(nft, "-j", "list", "chain", "inet", "vpn_panel", "leak_watch").Output() //nolint:gosec
	if err != nil {
		return 0, false
	}
	return parseCounter(out, nftgen.LeakWatchComment), true
}

func parseLeakDrops(out []byte) int64 { return parseCounter(out, nftgen.LeakDropComment) }

func parseCounter(out []byte, comment string) int64 {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string `json:"comment"`
				Expr    []struct {
					Counter *struct {
						Packets int64 `json:"packets"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return 0
	}
	var total int64
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment != comment {
			continue
		}
		for _, e := range item.Rule.Expr {
			if e.Counter != nil {
				total += e.Counter.Packets
			}
		}
	}
	return total
}

type firewallParams struct {
	Plan nftgen.FirewallPlan `json:"plan"`
}

func validateFirewallPlan(plan *nftgen.FirewallPlan, willProvision ...string) *agentrpc.ErrorObject {
	status, err := netstatus.Collect()
	if err != nil {
		return internalErr(errReadInterfaces, true)
	}
	knownNames := map[string]bool{}
	for _, i := range status.Interfaces {
		if !i.Loopback {
			knownNames[i.Name] = true
		}
	}

	for _, name := range willProvision {
		knownNames[name] = true
	}
	if err := plan.Validate(knownNames); err != nil {
		return &agentrpc.ErrorObject{Code: codeFwPlan, Message: err.Error(),
			Data: map[string]any{"recoverable": false}}
	}
	return nil
}

func (f *firewallApplier) firewallApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p firewallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку", Data: map[string]any{"recoverable": false}}
	}

	if rerr := f.sealedErr(); rerr != nil {
		return nil, rerr
	}
	facts := p.Plan
	plan := facts
	if f.composer != nil {
		plan = f.composer.FirewallWith(facts)
	}
	changed, rerr := f.applyPlanDirect(plan)
	if rerr != nil {
		return nil, rerr
	}
	if f.composer != nil {
		f.composer.SetFirewallFacts(facts)
	}
	return map[string]any{
		"changed":      changed,
		"ufw":          f.captureUFW(),
		"voip_warning": sipHelperWarning(),
	}, nil
}

func (f *firewallApplier) sealedErr() *agentrpc.ErrorObject {
	if f.composer == nil || !f.composer.Sealed() {
		return nil
	}
	return &agentrpc.ErrorObject{Code: codeFwSealed,
		Message: "настройки защищённого канала повреждены, поэтому офис закрыт от интернета — откройте страницу «VPN», проверьте режим, нажмите «Применить» и повторите",
		Data:    map[string]any{"recoverable": false}}
}

func (f *firewallApplier) lockDown() error {
	var ruleset []byte
	if f.composer != nil {
		if facts, ok := f.composer.FirewallFacts(); ok {
			ruleset = facts.Lockdown()
		}
	}
	if ruleset == nil {
		data, err := os.ReadFile(lockdownStatic)
		if err != nil {
			return err
		}
		ruleset = data
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.loadAndPersist(ruleset)
	return err
}

func (f *firewallApplier) applyPlanDirect(plan nftgen.FirewallPlan) (bool, *agentrpc.ErrorObject) {
	if rerr := validateFirewallPlan(&plan); rerr != nil {
		return false, rerr
	}
	ruleset := plan.Generate()

	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.dryRun(ruleset); err != nil {
		return false, &agentrpc.ErrorObject{Code: codeFwRules,
			Message: "правила не прошли проверку: " + err.Error(),
			Data:    map[string]any{"recoverable": false}}
	}
	changed, err := f.loadAndPersist(ruleset)
	if err != nil {
		return false, detailErr("не удалось применить правила защиты — попробуйте ещё раз; если повторяется, обратитесь в поддержку", err.Error(), true)
	}
	return changed, nil
}

func (f *firewallApplier) dryRun(ruleset []byte) error {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return err
	}
	if out, err := runStdin(nft, ruleset, "-c", "-f", "-"); err != nil {
		return &textError{firstLine(out)}
	}
	return nil
}

func (f *firewallApplier) load(ruleset []byte) error {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return err
	}
	if out, err := runStdin(nft, ruleset, "-f", "-"); err != nil {
		return &textError{"nft load: " + firstLine(out)}
	}
	return nil
}

func (f *firewallApplier) loadAndPersist(ruleset []byte) (bool, error) {
	if err := f.load(ruleset); err != nil {
		return false, err
	}
	if err := durable.MkdirAll(filepath.Dir(nftFile), 0o755); err != nil {
		return false, err
	}
	changed, err := durable.WriteIfChanged(nftFile, ruleset, 0o600)
	if err != nil {
		return false, err
	}
	f.applySysctl()
	return changed, nil
}

func (f *firewallApplier) snapshot() (prev []byte, existed bool) {
	data, err := os.ReadFile(nftFile)
	if err != nil {
		return nil, false
	}
	return data, true
}

func (f *firewallApplier) rollback(prev []byte, existed bool) {
	if existed {
		if err := f.load(prev); err != nil {
			log.Printf("firewall: rollback failed: %v", err)
			return
		}
		log.Printf("firewall: previous ruleset restored")
		return
	}
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return
	}
	_ = exec.Command(nft, "delete", "table", "inet", "vpn_panel").Run() //nolint:gosec
	log.Printf("firewall: table removed (no previous ruleset)")
}

func (f *firewallApplier) firewallStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return nil, internalErr(errToolMissing, false)
	}
	leaked, watched := f.leakWatch()
	out, err := exec.Command(nft, "list", "chain", "inet", "vpn_panel", "input").Output() //nolint:gosec
	if err != nil {

		return map[string]any{"input_filtered": false, "ping_answered": true, "ipv6_closed": false,
			"leak_watch": false, "leaked_outbound": 0, "intent_broken": f.intentLost()}, nil
	}
	text := string(out)
	return map[string]any{
		"input_filtered":  strings.Contains(text, "policy drop"),
		"ping_answered":   strings.Contains(text, "echo-request"),
		"ipv6_closed":     strings.Contains(text, "meta nfproto ipv6 drop"),
		"leak_watch":      watched,
		"leaked_outbound": leaked,
		"intent_broken":   f.intentLost(),
	}, nil
}

func (f *firewallApplier) intentLost() bool {
	if f.composer != nil && f.composer.Sealed() {
		return true
	}
	return f.intentBroken != nil && f.intentBroken()
}

func (f *firewallApplier) applySysctl() {
	if _, err := durable.WriteIfChanged(sysctlFile, []byte(sysctlContent), 0o644); err != nil {
		log.Printf("firewall: sysctl file not saved: %v", err)
	}
	if sysctl, err := findBinary([]string{"/usr/sbin/sysctl", "/sbin/sysctl"}); err == nil {
		_ = exec.Command(sysctl, "-w", "net.ipv4.ip_forward=1").Run() //nolint:gosec

		_ = exec.Command(sysctl, "-w", //nolint:gosec
			"net.netfilter.nf_conntrack_udp_timeout_stream="+strconv.Itoa(voipUDPStreamTimeout)).Run()
	}
}

func (f *firewallApplier) captureUFW() string {
	systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return "unknown"
	}
	state, _ := exec.Command(systemctl, "is-enabled", "ufw").Output() //nolint:gosec
	if strings.TrimSpace(string(state)) == "masked" {
		return "masked"
	}
	if ufw, err := findBinary([]string{"/usr/sbin/ufw", "/sbin/ufw"}); err == nil {
		_ = exec.Command(ufw, "disable").Run() //nolint:gosec
	}
	if err := exec.Command(systemctl, "mask", "ufw").Run(); err != nil { //nolint:gosec
		log.Printf("firewall: mask ufw failed: %v", err)
		return "mask_failed"
	}
	log.Printf("firewall: ufw disabled and masked")
	return "masked"
}

func sipHelperWarning() string {
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_helper"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			return "В системе включено автоматическое вмешательство в сигнализацию телефонии — возможны односторонний звук и обрывы. Обратитесь в поддержку."
		}
	}
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nf_nat_sip ") || strings.HasPrefix(line, "nf_conntrack_sip ") {
				fields := strings.Fields(line)

				if len(fields) >= 3 && fields[2] != "0" {
					return "Обнаружено вмешательство системы в сигнализацию телефонии — возможны односторонний звук и обрывы. Обратитесь в поддержку."
				}
			}
		}
	}
	return ""
}

type textError struct{ text string }

func (e *textError) Error() string { return e.text }

func runStdin(bin string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...) //nolint:gosec
	cmd.Stdin = strings.NewReader(string(stdin))
	return cmd.CombinedOutput()
}
