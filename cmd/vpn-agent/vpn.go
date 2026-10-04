package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/ovpngen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

const vpnStateFile = "/etc/vpn-panel/vpn.json"

const (
	nmDropInDir  = "/etc/NetworkManager/conf.d"
	nmDropInFile = "/etc/NetworkManager/conf.d/99-vpn-panel-wg.conf"
)

var nmDropInContent = func() string {
	var names []string
	for _, iface := range vpnproto.Ifaces() {
		names = append(names, "interface-name:"+iface)
	}
	return "[keyfile]\nunmanaged-devices=" + strings.Join(names, ";") + "\n"
}()

const nmConnFile = "/etc/NetworkManager/conf.d/99-vpn-panel-connectivity.conf"

const nmConnContent = "[connectivity]\nenabled=false\n"

const (
	modeWhite = "white"
	modeBlack = "black"
)

const (
	failStrict = "strict"
	failDirect = "direct"
)

const (
	codeVPNParams   = 1601
	codeVPNImport   = 1602
	codeVPNTool     = 1603
	codeVPNUp       = 1604
	codeVPNResolve  = 1605
	codeVPNBusy     = 1606
	codeVPNNotFound = 1607
	codeVPNActive   = 1608
)

var (
	pingCandidates  = []string{"/usr/bin/ping", "/bin/ping"}
	nmcliCandidates = []string{"/usr/bin/nmcli", "/bin/nmcli"}
)

type vpnPlan struct {
	Slug      string `json:"slug"`
	Protocol  string `json:"protocol,omitempty"`
	Mode      string `json:"mode"`
	OnFailure string `json:"on_failure"`
	MTU       int    `json:"mtu"`
}

type vpnModeState struct {
	Firewall nftgen.FirewallPlan `json:"firewall"`
	DNS      unboundgen.Plan     `json:"dns"`
	QoS      qosgen.Plan         `json:"qos"`
}

type vpnState struct {
	Plan         vpnPlan      `json:"plan"`
	White        vpnModeState `json:"white"`
	Black        vpnModeState `json:"black"`
	EndpointIP   string       `json:"endpoint_ip,omitempty"`
	EndpointPort int          `json:"endpoint_port,omitempty"`

	Transport string `json:"transport,omitempty"`

	Overhead int `json:"overhead,omitempty"`

	DataPlane vpndriver.Truth `json:"data_plane,omitempty"`

	Broken bool `json:"-"`
}

type vpnApplier struct {
	mu       sync.Mutex
	firewall *firewallApplier
	dns      *dnsApplier
	qos      *qosApplier
	drivers  map[vpndriver.Protocol]tunnelDriver

	composer *modeComposer

	watchMu sync.Mutex

	watchKick chan struct{}
	watchStop context.CancelFunc
	watch     watchdogState

	probe probeGuard
}

func newVPNApplier(f *firewallApplier, d *dnsApplier, q *qosApplier) *vpnApplier {
	return &vpnApplier{
		firewall: f, dns: d, qos: q, probe: newProbeGuard(), watchKick: make(chan struct{}, 1),
		drivers: newDrivers(),
	}
}

var driverCtors = map[vpndriver.Protocol]func() tunnelDriver{
	wggen.ID:   func() tunnelDriver { return &wgDriver{} },
	ovpngen.ID: func() tunnelDriver { return newOvpnDriver() },
}

func newDrivers() map[vpndriver.Protocol]tunnelDriver {
	out := map[vpndriver.Protocol]tunnelDriver{}
	for _, d := range vpnproto.All() {
		if ctor, ok := driverCtors[d.ID]; ok {
			out[d.ID] = ctor()
		}
	}
	return out
}

func (v *vpnApplier) driver(st *vpnState) tunnelDriver {
	p := vpndriver.Protocol(st.Plan.Protocol)
	if d, ok := v.drivers[p]; ok {
		return d
	}

	return unknownDriver{p}
}

func (v *vpnApplier) iface(st *vpnState) string { return v.driver(st).iface() }

func (v *vpnApplier) tunnelPresent() bool {
	st := v.readState()
	return v.driver(&st).present()
}

func (v *vpnApplier) readState() vpnState {
	data, err := os.ReadFile(vpnStateFile)
	return parseState(data, err, channelTraces)
}

func parseState(data []byte, readErr error, traces func() bool) vpnState {
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) && !traces() {
			return vpnState{Plan: vpnPlan{Mode: modeWhite, OnFailure: failStrict}}
		}
		return brokenState()
	}
	var st vpnState
	if err := json.Unmarshal(data, &st); err != nil {
		return brokenState()
	}
	if st.Plan.Mode != modeWhite && st.Plan.Mode != modeBlack {
		return brokenState()
	}
	st.Plan.OnFailure = normalizeOnFailure(st.Plan.OnFailure)
	st.Plan.Protocol = string(storedProtocol(st.Plan))
	return st
}

func brokenState() vpnState {
	return vpnState{Broken: true, Plan: vpnPlan{Mode: modeBlack, OnFailure: failStrict}}
}

func channelTraces() bool {
	for _, p := range []string{livePath(), ovpnLivePath()} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func storedProtocol(p vpnPlan) vpndriver.Protocol {
	if p.Protocol == "" && p.Slug == "" {
		return ""
	}
	return vpnproto.Stored(p.Protocol)
}

func normalizeOnFailure(v string) string {
	if v == failDirect {
		return failDirect
	}
	return failStrict
}

func (v *vpnApplier) writeState(st vpnState) error {
	if st.Broken {
		return errors.New("unreadable intent is never written back")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := durable.MkdirAll(filepath.Dir(vpnStateFile), 0o750); err != nil {
		return err
	}

	return durable.Write(vpnStateFile, append(data, '\n'), 0o600)
}

type vpnImportParams struct {
	Slug     string `json:"slug"`
	Protocol string `json:"protocol,omitempty"`
	Config   string `json:"config"`
}

func (v *vpnApplier) vpnImport(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p vpnImportParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	proto := vpnproto.Parse(p.Protocol)
	drv, ok := v.drivers[proto]
	if !ok {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "протокол подключения указан неверно — обновите страницу",
			Data:    map[string]any{"recoverable": false}}
	}
	if !vpndriver.ValidSlug(p.Slug) {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "имя профиля составлено неверно — задайте название латиницей или кириллицей",
			Data:    map[string]any{"recoverable": false}}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	meta, warnings, aerr := drv.importProfile(p.Slug, p.Config)
	if aerr != nil {
		return nil, aerr
	}
	log.Printf("vpn: profile %q imported (%s)", p.Slug, proto)
	return map[string]any{
		"meta":     meta,
		"warnings": warnings,
	}, nil
}

type vpnApplyParams struct {
	Plan  vpnPlan      `json:"plan"`
	White vpnModeState `json:"white"`
	Black vpnModeState `json:"black"`
}

func (v *vpnApplier) vpnApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p vpnApplyParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	if p.Plan.Mode != modeWhite && p.Plan.Mode != modeBlack {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "режим работы канала указан неверно — обновите страницу",
			Data:    map[string]any{"recoverable": false}}
	}
	p.Plan.OnFailure = normalizeOnFailure(p.Plan.OnFailure)

	proto := vpnproto.Parse(p.Plan.Protocol)
	if (proto != "" || p.Plan.Slug != "") && !vpnproto.Known(proto) {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "протокол подключения указан неверно — обновите страницу",
			Data:    map[string]any{"recoverable": false}}
	}
	p.Plan.Protocol = string(proto)
	if p.Plan.MTU != 0 && (p.Plan.MTU < vpndriver.MinMTU || p.Plan.MTU > vpndriver.MaxMTU) {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: fmt.Sprintf("размер пакетов должен быть от %d до %d — исправьте значение", vpndriver.MinMTU, vpndriver.MaxMTU),
			Data:    map[string]any{"recoverable": false}}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.composer.Unseal() {
		log.Printf("vpn: the administrator chose the mode again, the closed state is lifted")
	}
	prev := v.readState()
	st := vpnState{Plan: p.Plan, White: p.White, Black: p.Black, EndpointIP: prev.EndpointIP, Transport: prev.Transport}
	changed, aerr := v.applyState(&st, true)

	if err := v.writeState(st); err != nil && aerr == nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}

	v.restartWatchdog(st)
	if aerr != nil {
		return nil, aerr
	}
	return map[string]any{"changed": changed, "mode": st.Plan.Mode, "endpoint_ip": st.EndpointIP}, nil
}

func (v *vpnApplier) applyState(st *vpnState, newIntent bool) (bool, *agentrpc.ErrorObject) {
	if st.Plan.Mode == modeBlack {
		if st.Plan.Slug == "" {
			return false, &agentrpc.ErrorObject{Code: codeVPNParams,
				Message: "не выбрано подключение — загрузите файл конфигурации на странице «Защищённый канал»",
				Data:    map[string]any{"recoverable": false}}
		}

		v.downOthers(st)
		if newIntent {

			v.clearPause(st)
		}

		v.patchOutputChain(st)

		if err := ensureKillRoutes(vpndriver.Mark); err != nil {
			log.Printf("vpn: kill routes not applied: %v", err)
		}
		v.composer.SetOverlay(v.overlayOf(st))
		tunnelChanged, aerr := v.bringUpIntent(st, newIntent)
		if aerr != nil {
			return false, aerr
		}
		fwChanged, aerr := v.applyBlackServices(st)
		if aerr != nil {
			return false, aerr
		}

		st.DataPlane = v.dataPlane()
		if st.DataPlane.IsNo() {
			log.Printf("vpn: tunnel is up but no data passes through it")
		}
		return tunnelChanged || fwChanged, nil
	}

	ensureConnectivityCheck(false)

	v.composer.SetOverlay(modeOverlay{})
	fwChanged, aerr := v.firewall.applyPlanDirect(v.composer.Firewall(st.White.Firewall))
	if aerr != nil {
		return false, aerr
	}
	if _, aerr := v.dns.applyPlan(v.composer.DNS(st.White.DNS)); aerr != nil {
		return false, aerr
	}
	if _, aerr := v.qos.applyAndPersist(v.composer.QoS(st.White.QoS)); aerr != nil {
		return false, aerr
	}
	down := v.bringDown(st)
	v.downOthers(st)

	removeTunnelRoutes()
	return fwChanged || down, nil
}

func (v *vpnApplier) downOthers(st *vpnState) {
	active := v.driver(st)
	for _, d := range v.drivers {
		if d != active && d.present() {
			log.Printf("vpn: tunnel of another protocol (%s) is up, bringing it down", d.protocol())
			d.down()
		}
	}
}

func (v *vpnApplier) applyBlackServices(st *vpnState) (bool, *agentrpc.ErrorObject) {
	drv := v.driver(st)
	v.patchOutputChain(st)

	ensureNMDropIn()
	ensureConnectivityCheck(true)

	var firstErr *agentrpc.ErrorObject
	keep := func(e *agentrpc.ErrorObject) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	v.composer.SetOverlay(v.overlayOf(st))
	fwChanged, aerr := v.firewall.applyPlanDirect(v.composer.Firewall(st.Black.Firewall))
	keep(aerr)
	deferred := false
	if err := drv.ensureRoutes(); err != nil {
		log.Printf("vpn: tunnel routes not applied yet: %v", err)
		deferred = true
	}

	if !drv.present() {
		log.Printf("vpn: tunnel queue deferred until the tunnel is up")
		deferred = true
	} else if plan := v.composer.QoS(st.Black.QoS); queueWaitsForWAN(plan, ifacePresent) {
		log.Printf("vpn: queue deferred: provider interface %q is gone after the path change, waiting for new network facts", plan.WAN)
		deferred = true
	} else if _, aerr := v.qos.applyAndPersist(plan); aerr != nil {
		keep(aerr)
		deferred = true
	}

	bind := drv.passport(st.Transport).AddressAtImport
	if !bind {
		if addr := drv.facts().TunnelIPv4; addr == "" {
			log.Printf("vpn: resolver binding deferred until the tunnel is connected")
			deferred = true
		} else {
			st.Black.DNS.OutgoingAddress = addr
			bind = true
		}
	}
	if bind {
		v.composer.SetOverlay(v.overlayOf(st))
		if _, aerr := v.dns.applyPlan(v.composer.DNS(st.Black.DNS)); aerr != nil {
			keep(aerr)
			deferred = true
		}
	}
	if !deferred && firstErr == nil {
		v.markServicesPending(false)
	}
	return fwChanged, firstErr
}

func queueWaitsForWAN(plan qosgen.Plan, present func(string) bool) bool {
	return plan.Enabled && plan.WAN != "" && !present(plan.WAN)
}

func ensureConnectivityCheck(disable bool) {
	if _, err := os.Stat(nmDropInDir); err != nil {
		return
	}
	cur, _ := os.ReadFile(nmConnFile) //nolint:gosec
	if disable {
		if string(cur) == nmConnContent {
			return
		}
		if err := durable.Write(nmConnFile, []byte(nmConnContent), 0o644); err != nil {
			log.Printf("vpn: connectivity check drop-in: %v", err)
			return
		}
		log.Printf("vpn: desktop connectivity check disabled in protected mode")
	} else {
		if len(cur) == 0 {
			return
		}
		if err := durable.Remove(nmConnFile); err != nil {
			log.Printf("vpn: connectivity check drop-in: %v", err)
			return
		}
		log.Printf("vpn: desktop connectivity check restored")
	}
	if nmcli, err := findBinary(nmcliCandidates); err == nil {
		_ = exec.Command(nmcli, "general", "reload", "conf").Run() //nolint:gosec
	}
}

func (v *vpnApplier) patchOutputChain(st *vpnState) {
	t := st.Black.Firewall.Tunnel
	if t == nil {
		return
	}
	t.Endpoint = st.EndpointIP
	t.EndpointPort = st.EndpointPort
	t.EndpointProto = st.Transport
	t.Mark = currentTunnelFwmark()
}

func (v *vpnApplier) overlayOf(st *vpnState) modeOverlay {
	drv := v.driver(st)
	var o modeOverlay
	if drv.passport(st.Transport).AddressAtImport {
		o.DNSOut = st.Black.DNS.OutgoingAddress
	} else {
		o.DNSOut = drv.facts().TunnelIPv4
	}
	if t := st.Black.Firewall.Tunnel; t != nil {
		c := *t

		c.Address = o.DNSOut
		o.Tunnel = &c
	}
	if drv.present() {
		o.QoSTunnel = st.Black.QoS.Tunnel
	}
	return o
}

func (v *vpnApplier) onPathChanged() {
	v.mu.Lock()
	st := v.readState()
	if st.Plan.Mode != modeBlack || st.Plan.Slug == "" {
		v.mu.Unlock()
		return
	}
	log.Printf("vpn: provider path changed, the tunnel follows it")
	_, aerr := v.applyState(&st, true)
	if err := v.writeState(st); err != nil {
		log.Printf("vpn: state write after path change: %v", err)
	}
	v.mu.Unlock()
	if aerr != nil {
		log.Printf("vpn: tunnel did not follow the new path: %s", aerr.Message)
	}
	v.restartWatchdog(st)
}

func (v *vpnApplier) bringUp(st *vpnState) (bool, *agentrpc.ErrorObject) {
	return v.bringUpIntent(st, false)
}

func (v *vpnApplier) bringUpIntent(st *vpnState, newIntent bool) (bool, *agentrpc.ErrorObject) {

	if !newIntent && pausedForPlan(st.Plan) {
		log.Printf("vpn: connection attempts are stopped for this profile, waiting for the administrator")
		return false, nil
	}
	drv := v.driver(st)
	res, aerr := drv.up(upRequest{Slug: st.Plan.Slug, MTU: st.Plan.MTU, Mark: currentTunnelFwmark(), NewIntent: newIntent})
	if aerr != nil {
		return false, aerr
	}
	st.EndpointIP, st.EndpointPort, st.Transport, st.Overhead = res.EndpointIP, res.EndpointPort, res.Transport, res.Overhead
	if !res.Changed {
		return false, nil
	}
	v.markUp()

	v.markServicesPending(true)

	if drv.present() {
		log.Printf("vpn: tunnel is up (%s, endpoint %s)", drv.protocol(), res.EndpointIP)
	} else {
		log.Printf("vpn: tunnel start requested (%s, endpoint %s), the service is bringing it up",
			drv.protocol(), res.EndpointIP)
	}
	return true, nil
}

func errStartRefused() *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: codeVPNUp,
		Message: "Канал не поднялся после нескольких попыток подряд. Автоматические попытки прекращены — нажмите «Применить», когда будете готовы.",
		Data:    map[string]any{"recoverable": true, "start_refused": true}}
}

func isStartRefused(e *agentrpc.ErrorObject) bool {
	return e != nil && e.Data["start_refused"] == true
}

func (v *vpnApplier) bringDown(st *vpnState) bool {
	if v.driver(st).down() {
		log.Printf("vpn: tunnel is down")
		return true
	}
	return false
}

func resolveEndpointAddr(host string, mark int) (string, *agentrpc.ErrorObject) {
	if ip := net.ParseIP(host); ip != nil {
		if !vpndriver.UsableEndpoint(ip) {
			return "", &agentrpc.ErrorObject{Code: codeVPNResolve,
				Message: "адрес сервера подключения служебный — по такому адресу канал работать не может; запросите у поставщика правильный файл",
				Data:    map[string]any{"recoverable": false}}
		}
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	var lastErr error
	for _, upstream := range unboundgen.Upstream {
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second, Control: markSocket(mark)}
				return d.DialContext(ctx, network, net.JoinHostPort(upstream, "53"))
			},
		}
		addrs, err := res.LookupIP(ctx, "ip4", host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, addr := range addrs {

			if vpndriver.UsableEndpoint(addr) {
				return addr.String(), nil
			}
			lastErr = fmt.Errorf("имя сервера разрешилось в служебный адрес %s", addr)
		}
	}
	detail := ""
	if lastErr != nil {
		detail = lastErr.Error()
	}
	return "", &agentrpc.ErrorObject{Code: codeVPNResolve,
		Message: "не удалось определить адрес сервера подключения. Проверьте, что сервер видит интернет, и попробуйте ещё раз",
		Data:    map[string]any{"recoverable": true, "detail": detail}}
}

func markSocket(mark int) func(network, address string, c syscall.RawConn) error {

	if mark == 0 {
		mark = vpndriver.Mark
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {

			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return serr
	}
}

func (v *vpnApplier) currentFwmark() int { return currentTunnelFwmark() }

var liveMarkReaders = []func() (int, bool){wgLiveMark}

func currentTunnelFwmark() int {
	for _, read := range liveMarkReaders {
		if mark, ok := read(); ok {
			return mark
		}
	}
	return vpndriver.Mark
}

func ensureNMDropIn() {
	if cur, err := os.ReadFile(nmDropInFile); err == nil && string(cur) == nmDropInContent { //nolint:gosec
		return
	}
	if _, err := os.Stat(nmDropInDir); err != nil {
		return
	}
	if err := durable.Write(nmDropInFile, []byte(nmDropInContent), 0o644); err != nil {
		log.Printf("vpn: network manager drop-in: %v", err)
		return
	}
	if nmcli, err := findBinary(nmcliCandidates); err == nil {
		_ = exec.Command(nmcli, "general", "reload", "conf").Run() //nolint:gosec
	}
	log.Printf("vpn: tunnel interfaces excluded from the desktop network manager")
}

func (v *vpnApplier) vpnStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	st := v.readState()
	drv := v.driver(&st)
	res := map[string]any{
		"mode": st.Plan.Mode,

		"intent_broken": st.Broken || v.composer.Sealed(),
		"slug":          st.Plan.Slug,
		"protocol":      string(drv.protocol()),
		"transport":     st.Transport,
		"on_failure":    st.Plan.OnFailure,
		"mtu_wanted":    st.Plan.MTU,
		"present":       false,
		"online":        false,
		"profiles":      v.listProfiles(),
		"iface":         drv.iface(),
	}
	if st.EndpointIP != "" {
		res["endpoint_ip"] = st.EndpointIP
	}
	wd := v.watchdogSnapshot()
	res["degraded"] = wd.Degraded
	res["retry_in_sec"] = wd.RetryInSec

	load1, cores := loadAverage()
	res["cores"] = cores
	res["load1"] = load1
	res["aes_ni"] = cpuHasAES()
	res["data_plane"] = st.DataPlane.String()

	res["blocked_outbound"] = v.firewall.leakDrops()
	res["outbound_guard"] = st.Black.Firewall.Tunnel != nil && st.Black.Firewall.Tunnel.Endpoint != "" && st.Plan.Mode == modeBlack

	f := drv.facts()
	pass := drv.passport(st.Transport)
	if f.Present {
		pass.KernelDataPlane = f.KernelDataPlane
	}
	res["passport"] = pass
	res["kernel_data_plane"] = pass.KernelDataPlane
	if len(f.Pushed) > 0 {
		res["server_pushed"] = f.Pushed
	}

	if f.PeerIPv4 != "" {
		res["peer_ipv4"] = f.PeerIPv4
	}

	if f.ProcState != "" {
		res["proc_state"] = f.ProcState
	}
	if f.FailReason != "" {
		res["fail_reason"] = f.FailReason
		res["fail_count"] = f.FailCount
		res["last_fail_unix"] = f.LastFailUnix
	}

	if w := v.watchdogSnapshot(); w.Paused {
		res["retry_paused"] = true
	}

	res["session"] = map[string]int64{"id": wd.Session, "since": wd.SessionSince}

	res["self_healing"] = f.ProcRunning && pass.Liveness == vpndriver.LivenessProcess && !f.Connected

	res["data_dead"], res["data_suspect"] = wd.DataDead, wd.DataSuspect
	res["data_restarts"], res["data_restart_budget"] = wd.DataRestarts, dataRestartBudget
	if !f.Present {
		return res, nil
	}
	res["present"] = true
	res["mtu"] = readIfaceMTU(drv.iface())
	res["rx_bytes"], res["tx_bytes"] = f.RxBytes, f.TxBytes
	if f.Endpoint != "" {
		res["endpoint"] = f.Endpoint
	}
	if f.Connected {
		res["handshake_age_sec"] = f.AgeSec
		online := f.AgeSec <= staleAfter(drv.passport(st.Transport))
		res["online"] = online

		if online && st.Plan.Mode == modeBlack {
			res["data_plane"] = v.dataPlane().String()
		}
	}
	return res, nil
}

func readIfaceMTU(name string) int {

	data, err := os.ReadFile("/sys/class/net/" + name + "/mtu") //nolint:gosec
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return v
}

func ifaceIPv4(name string) string {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return ""
	}
	out, err := exec.Command(ipBin, "-4", "-j", "addr", "show", "dev", name).Output() //nolint:gosec
	if err != nil {
		return ""
	}
	var links []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(out, &links) != nil {
		return ""
	}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			if ip := net.ParseIP(a.Local); ip != nil && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func ifaceKind(name string) string {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return ""
	}
	out, err := exec.Command(ipBin, "-j", "-d", "link", "show", "dev", name).Output() //nolint:gosec
	if err != nil {
		return ""
	}
	var links []struct {
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(out, &links) != nil || len(links) == 0 {
		return ""
	}
	return links[0].LinkInfo.Kind
}

func ifacePresent(name string) bool {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return false
	}
	return exec.Command(ipBin, "link", "show", "dev", name).Run() == nil //nolint:gosec
}

func ifaceCounters(name string) (rx, tx int64) {

	read := func(f string) int64 {
		data, err := os.ReadFile("/sys/class/net/" + name + "/statistics/" + f) //nolint:gosec
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return n
	}
	return read("rx_bytes"), read("tx_bytes")
}

func ifacePackets(name string) (rx, tx int64) {

	read := func(f string) int64 {
		data, err := os.ReadFile("/sys/class/net/" + name + "/statistics/" + f) //nolint:gosec
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return n
	}
	return read("rx_packets"), read("tx_packets")
}

func (v *vpnApplier) listProfiles() []string {
	out := []string{}
	for _, d := range v.drivers {
		out = append(out, d.listProfiles()...)
	}
	return out
}

type vpnRemoveParams struct {
	Slug     string `json:"slug"`
	Protocol string `json:"protocol,omitempty"`
}

func (v *vpnApplier) vpnRemove(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p vpnRemoveParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	if !vpndriver.ValidSlug(p.Slug) {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "имя профиля составлено неверно — обновите страницу",
			Data:    map[string]any{"recoverable": false}}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	st := v.readState()
	if st.Plan.Mode == modeBlack && st.Plan.Slug == p.Slug {
		return nil, &agentrpc.ErrorObject{Code: codeVPNActive,
			Message: "это подключение сейчас используется — сначала переключите офис на прямой доступ в интернет, потом удаляйте",
			Data:    map[string]any{"recoverable": false}}
	}

	drivers := []tunnelDriver{}
	if p.Protocol != "" {
		if d, ok := v.drivers[vpnproto.Parse(p.Protocol)]; ok {
			drivers = append(drivers, d)
		}
	} else {
		for _, d := range v.drivers {
			drivers = append(drivers, d)
		}
	}
	for _, d := range drivers {
		if err := d.removeProfile(p.Slug, st.Plan.Slug == p.Slug); err != nil {
			return nil, detailErr("не удалось удалить подключение с сервера — обратитесь в поддержку", err.Error(), true)
		}
	}
	if st.Plan.Slug == p.Slug {
		st.Plan.Slug = ""
		if err := v.writeState(st); err != nil {
			log.Printf("vpn: state write after removal: %v", err)
		}
	}
	log.Printf("vpn: profile %q removed", p.Slug)
	return map[string]any{"removed": true}, nil
}

func (v *vpnApplier) RestoreOnStart() {
	st := v.readState()

	if st.Broken || (st.Plan.Mode == modeBlack && st.Plan.Slug == "") {
		v.closeOffice()
		return
	}
	if st.Plan.Mode != modeBlack {
		return
	}
	v.mu.Lock()
	if _, aerr := v.applyState(&st, false); aerr != nil {
		v.mu.Unlock()
		log.Printf("vpn: restore failed: %s", aerr.Message)

		v.restartWatchdog(st)
		go v.retryRestore()
		return
	}
	if err := v.writeState(st); err != nil {
		log.Printf("vpn: state write on restore: %v", err)
	}
	v.mu.Unlock()
	v.restartWatchdog(st)
	log.Printf("vpn: tunnel restored in protected mode")
}

func (v *vpnApplier) closeOffice() {
	v.composer.Seal()
	if err := v.firewall.lockDown(); err != nil {
		log.Printf("vpn: intent is unreadable, emergency ruleset not loaded: %v", err)
		return
	}
	log.Printf("vpn: intent is unreadable, the office is closed until the administrator chooses the mode again")
}

func (v *vpnApplier) retryRestore() {
	for attempt := 2; attempt <= 4; attempt++ {
		time.Sleep(time.Duration(attempt*5) * time.Second)
		st := v.readState()
		if st.Plan.Mode != modeBlack || st.Plan.Slug == "" {
			return
		}
		if pausedForPlan(st.Plan) {
			return
		}
		v.mu.Lock()
		_, aerr := v.applyState(&st, false)
		if aerr == nil {
			if err := v.writeState(st); err != nil {
				log.Printf("vpn: state write on restore: %v", err)
			}
		}
		v.mu.Unlock()
		if aerr == nil {
			log.Printf("vpn: protected mode restored on attempt %d", attempt)
			return
		}
		log.Printf("vpn: restore attempt %d failed: %s", attempt, aerr.Message)
	}
}

const dataProbeAttempts = 3

func (v *vpnApplier) dataPlane() vpndriver.Truth {

	for attempt := 0; attempt < dataProbeAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		if v.dataPlaneAttempt() {
			return vpndriver.Yes
		}
	}
	if !v.dataProbeReady() {
		return vpndriver.Unknown
	}
	return vpndriver.No
}

func (v *vpnApplier) dataProbeReady() bool {
	st := v.readState()
	drv := v.driver(&st)
	f := drv.facts()
	return f.Present && f.Connected && !f.ServicesMissing
}

func (v *vpnApplier) dataPlaneAttempt() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for _, upstream := range unboundgen.Upstream {
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(upstream, "53"))
			},
		}

		if addrs, err := res.LookupIP(ctx, "ip4", dataProbeName); err == nil && len(addrs) > 0 {
			return true
		}
	}
	return false
}

const dataProbeName = "dns.quad9.net"

func cpuHasAES() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") && strings.Contains(line, " aes") {
			return true
		}
	}
	return false
}

func invalidParams() *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
		Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку",
		Data:    map[string]any{"recoverable": false}}
}
