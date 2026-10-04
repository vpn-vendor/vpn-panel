package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/dnsinfra"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

const (
	codeDNSPlan      = 1302
	codeDNSNoTool    = 1303
	codeDNSConfig    = 1304
	codeDNSPortBusy  = 1305
	codeDNSInfraBusy = 1306
	codeDNSInfra     = 1307
)

const (
	unboundFile     = "/etc/unbound/unbound.conf.d/vpn-panel.conf"
	unboundService  = "unbound.service"
	resolvedDropDir = "/etc/systemd/resolved.conf.d"
	resolvedDropIn  = "/etc/systemd/resolved.conf.d/vpn-panel.conf"
)

const resolvedDropInContent = `[Resolve]
DNS=127.0.0.1
Domains=~.
DNSStubListener=yes
`

type dnsApplier struct {
	mu sync.Mutex

	infraLimit *ratelimit.Limiter

	composer *modeComposer
}

func newDNSApplier() *dnsApplier { return &dnsApplier{} }

type dnsParams struct {
	Plan unboundgen.Plan `json:"plan"`
}

func (d *dnsApplier) dnsApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p dnsParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку", Data: map[string]any{"recoverable": false}}
	}

	plan := p.Plan
	if d.composer != nil {
		plan = d.composer.DNSWith(p.Plan)
	}
	res, aerr := d.applyPlan(plan)
	if aerr == nil && d.composer != nil {
		d.composer.SetDNSFacts(p.Plan)
	}
	return res, aerr
}

func (d *dnsApplier) applyPlan(plan unboundgen.Plan) (any, *agentrpc.ErrorObject) {
	p := dnsParams{Plan: plan}

	status, err := netstatus.Collect()
	if err != nil {
		return nil, internalErr(errReadInterfaces, true)
	}
	known := map[string]bool{}
	for _, i := range status.Interfaces {
		if !i.Loopback {
			known[i.Name] = true
		}
	}
	if err := p.Plan.Validate(known); err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDNSPlan, Message: err.Error(),
			Data: map[string]any{"recoverable": false}}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	unboundBin, err := findBinary([]string{"/usr/sbin/unbound", "/sbin/unbound"})
	if err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDNSNoTool,
			Message: "служба разрешения имён не установлена",
			Data:    map[string]any{"recoverable": false}}
	}
	_ = unboundBin

	if busy := busyAddress(p.Plan.ListenAddresses()); busy != "" && !ourServiceRunning() {
		return nil, &agentrpc.ErrorObject{Code: codeDNSPortBusy,
			Message: "адрес " + busy + ":53 занят другой службой — разрешение имён не настроено",
			Data:    map[string]any{"recoverable": false}}
	}

	config := p.Plan.Generate()

	staged, err := durable.Stage(unboundFile, config, 0o644)
	if err != nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}
	defer staged.Abort()
	if checkconf, err := findBinary([]string{"/usr/sbin/unbound-checkconf", "/sbin/unbound-checkconf"}); err == nil {
		if out, cerr := exec.Command(checkconf, staged.Path()).CombinedOutput(); cerr != nil { //nolint:gosec
			return nil, &agentrpc.ErrorObject{Code: codeDNSConfig,
				Message: "конфигурация разрешения имён не прошла проверку: " + firstLine(out),
				Data:    map[string]any{"recoverable": false}}
		}
	}

	changed := true
	needRestart := false
	if cur, err := os.ReadFile(unboundFile); err == nil { //nolint:gosec
		changed = string(cur) != string(config)
		needRestart = outgoingChanged(cur, config)
	}
	if changed {
		if err := staged.Commit(); err != nil {
			return nil, detailErr(errWriteConfig, err.Error(), true)
		}
	}

	resolvedChanged := ensureResolvedDropIn()
	state := ensureUnbound(changed, needRestart, p.Plan.ListenAddresses())

	if p.Plan.OutgoingAddress != "" && !resolvesExternal() {
		log.Printf("dns: resolver does not answer for external names after tunnel change, restarting it")
		if systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
			if out, rerr := exec.Command(systemctl, "restart", unboundService).CombinedOutput(); rerr != nil { //nolint:gosec
				log.Printf("dns: restart failed: %s", firstLine(out))
			}
		}
	}

	verified := resolverAnswers("127.0.0.1:53")
	if resolvedChanged {
		restartResolved()
	}
	return map[string]any{
		"changed":   changed || resolvedChanged,
		"state":     state,
		"verified":  verified,
		"listening": p.Plan.ListenAddresses(),
	}, nil
}

func busyAddress(addrs []string) string {
	for _, a := range addrs {
		ln, err := net.ListenPacket("udp", net.JoinHostPort(a, "53"))
		if err != nil {
			return a
		}
		_ = ln.Close()
	}
	return ""
}

func ourServiceRunning() bool {
	systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return false
	}
	out, _ := exec.Command(systemctl, "is-active", unboundService).Output() //nolint:gosec
	return isOurServiceState(strings.TrimSpace(string(out)))
}

func isOurServiceState(state string) bool {
	switch state {
	case "active", "activating", "reloading", "refreshing":
		return true
	}
	return false
}

func outgoingChanged(oldCfg, newCfg []byte) bool {
	return outgoingLines(oldCfg) != outgoingLines(newCfg)
}

func outgoingLines(cfg []byte) string {
	var out []string
	for _, line := range strings.Split(string(cfg), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "outgoing-interface:") || strings.HasPrefix(t, "do-ip6:") {
			out = append(out, t)
		}
	}
	return strings.Join(out, "|")
}

func ensureUnbound(changed, restart bool, addrs []string) string {
	systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return "unknown"
	}
	active := exec.Command(systemctl, "is-active", "--quiet", unboundService).Run() == nil //nolint:gosec
	switch {
	case !active:
		if out, err := exec.Command(systemctl, "enable", "--now", unboundService).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("dns: enable failed: %s", firstLine(out))
			return "failed"
		}
	case restart:
		if out, err := exec.Command(systemctl, "restart", unboundService).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("dns: restart failed: %s", firstLine(out))
		}
	case changed:
		if err := exec.Command(systemctl, "reload", unboundService).Run(); err != nil { //nolint:gosec
			log.Printf("dns: reload failed, restarting")
			_ = exec.Command(systemctl, "restart", unboundService).Run() //nolint:gosec
		}
	}
	if !answersOnAll(addrs) {
		if out, err := exec.Command(systemctl, "restart", unboundService).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("dns: restart failed: %s", firstLine(out))
		}
	}
	if exec.Command(systemctl, "is-active", "--quiet", unboundService).Run() == nil { //nolint:gosec
		return "active"
	}
	return "inactive"
}

func answersOnAll(addrs []string) bool {
	for _, a := range addrs {
		if !resolverAnswers(net.JoinHostPort(a, "53")) {
			return false
		}
	}
	return true
}

func ensureResolvedDropIn() bool {
	if err := durable.MkdirAll(resolvedDropDir, 0o755); err != nil {
		log.Printf("dns: resolved drop-in dir: %v", err)
		return false
	}
	changed, err := durable.WriteIfChanged(resolvedDropIn, []byte(resolvedDropInContent), 0o644)
	if err != nil {
		log.Printf("dns: resolved drop-in: %v", err)
		return false
	}
	return changed
}

func restartResolved() {
	if systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
		_ = exec.Command(systemctl, "restart", "systemd-resolved.service").Run() //nolint:gosec
	}
}

func resolvesExternal() bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, uncacheableProbeName())
	if err == nil && len(ips) > 0 {
		return true
	}

	var derr *net.DNSError
	if errors.As(err, &derr) && derr.IsNotFound {
		return true
	}
	return false
}

func uncacheableProbeName() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {

		return fmt.Sprintf("%d.%s", time.Now().UnixNano(), externalProbeZone)
	}
	return fmt.Sprintf("%x.%s", b, externalProbeZone)
}

const externalProbeZone = "dns.quad9.net"

func resolverAnswers(addr string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, unboundgen.LocalDomain)
	return err == nil && len(ips) > 0
}

func (d *dnsApplier) dnsInfra(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		Only []string `json:"only"`
	}
	_ = json.Unmarshal(raw, &p)
	if d.infraLimit == nil {
		d.infraLimit = ratelimit.New(6, 1, 10*time.Second)
	}
	if !d.infraLimit.Allow("infra") {
		return nil, agentrpc.Busy(codeDNSInfraBusy, "слишком частые чтения задержек резолвера", d.infraLimit.RetryIn("infra"))
	}
	control, err := findBinary([]string{"/usr/sbin/unbound-control", "/sbin/unbound-control"})
	if err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDNSInfra, Message: "утилита управления резолвером не найдена", Data: map[string]any{"recoverable": false}}
	}
	out, err := exec.Command(control, "dump_infra").Output() //nolint:gosec
	if err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDNSInfra, Message: "резолвер не отдал кэш задержек", Data: map[string]any{"recoverable": true}}
	}

	var only []string
	for _, ip := range p.Only {
		if net.ParseIP(ip) != nil {
			only = append(only, ip)
		}
	}
	return map[string]any{"servers": dnsinfra.Parse(out, only)}, nil
}
