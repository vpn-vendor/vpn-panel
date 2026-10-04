package main

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	probeMTUTimeout  = 40 * time.Second
	probeMTUStepWait = 1
	probeMTUMaxSteps = 12
)

type probeGuard struct {
	mu      sync.Mutex
	limiter *ratelimit.Limiter
	running bool
}

func newProbeGuard() probeGuard {

	return probeGuard{limiter: ratelimit.New(1, 1, time.Minute)}
}

type vpnProbeParams struct {
	InnerTarget string `json:"inner_target,omitempty"`
}

type legResult struct {
	Found   bool `json:"found"`
	PathMTU int  `json:"path_mtu"`
}

func (v *vpnApplier) vpnMTUProbe(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p vpnProbeParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalidParams()
		}
	}
	innerTarget := unboundgen.Upstream[0]
	if p.InnerTarget != "" {
		ip := net.ParseIP(p.InnerTarget)
		if ip == nil || ip.To4() == nil {
			return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
				Message: "адрес для проверки указан неверно — обновите страницу",
				Data:    map[string]any{"recoverable": false}}
		}
		innerTarget = ip.String()
	}

	st := v.readState()
	if st.EndpointIP == "" {
		return nil, &agentrpc.ErrorObject{Code: codeVPNNotFound,
			Message: "адрес сервера подключения ещё не известен — сначала включите защищённый канал",
			Data:    map[string]any{"recoverable": false}}
	}
	if !v.probe.limiter.Allow("mtu") {
		return nil, agentrpc.Busy(codeVPNBusy, "подбор запускался меньше минуты назад — подождите", v.probe.limiter.RetryIn("mtu"))
	}
	v.probe.mu.Lock()
	if v.probe.running {
		v.probe.mu.Unlock()
		return nil, &agentrpc.ErrorObject{Code: codeVPNBusy,
			Message: "подбор уже идёт — дождитесь результата",
			Data:    map[string]any{"recoverable": true}}
	}
	v.probe.running = true
	v.probe.mu.Unlock()
	defer func() { v.probe.mu.Lock(); v.probe.running = false; v.probe.mu.Unlock() }()

	pingBin, err := findBinary(pingCandidates)
	if err != nil {
		return nil, internalErr(errToolMissing, false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeMTUTimeout)
	defer cancel()

	mark := v.currentFwmark()
	iface := v.iface(&st)
	overhead := v.driver(&st).passport(st.Transport).OverheadIPv4
	if st.Overhead > 0 {
		overhead = st.Overhead
	}
	outer := searchPath(ctx, func(size int) bool {
		args := []string{"-M", "do", "-c", "1", "-W", strconv.Itoa(probeMTUStepWait), "-s", strconv.Itoa(size)}
		if mark > 0 {
			args = append(args, "-m", strconv.Itoa(mark))
		}
		return pingOK(ctx, pingBin, append(args, st.EndpointIP))
	}, vpndriver.ProbeHigh)

	inner := legResult{}
	if v.tunnelPresent() {
		high := readIfaceMTU(iface) - vpndriver.ProbeHeader
		if high > vpndriver.ProbeHigh {
			high = vpndriver.ProbeHigh
		}
		inner = searchPath(ctx, func(size int) bool {
			return pingOK(ctx, pingBin, []string{"-M", "do", "-c", "1",
				"-W", strconv.Itoa(probeMTUStepWait), "-I", iface,
				"-s", strconv.Itoa(size), innerTarget})
		}, high)
	}

	recommended := 0
	if outer.Found {
		recommended = vpndriver.TunnelMTU(outer.PathMTU, overhead)
	}
	if inner.Found && (recommended == 0 || inner.PathMTU < recommended) {
		recommended = inner.PathMTU
		if recommended < vpndriver.MinMTU {
			recommended = vpndriver.MinMTU
		}
	}

	blackhole := inner.Found && inner.PathMTU < readIfaceMTU(iface)

	return map[string]any{
		"outer":        outer,
		"inner":        inner,
		"recommended":  recommended,
		"blackhole":    blackhole,
		"deadline_hit": ctx.Err() != nil,
	}, nil
}

func searchPath(ctx context.Context, pass func(int) bool, high int) legResult {
	if high < vpndriver.ProbeLow {
		return legResult{}
	}
	if pass(high) {
		return legResult{Found: true, PathMTU: high + vpndriver.ProbeHeader}
	}
	low := vpndriver.ProbeLow
	if !pass(low) {

		return legResult{}
	}
	for steps := 0; steps < probeMTUMaxSteps; steps++ {
		if ctx.Err() != nil {
			break
		}
		mid := vpndriver.NextProbe(low, high)
		if mid == 0 {
			break
		}
		if pass(mid) {
			low = mid
		} else {
			high = mid
		}
	}
	return legResult{Found: true, PathMTU: low + vpndriver.ProbeHeader}
}

func pingOK(ctx context.Context, bin string, args []string) bool {
	return exec.CommandContext(ctx, bin, args...).Run() == nil //nolint:gosec
}
