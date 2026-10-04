package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpncheck"
)

const (
	measurePayload  = 56
	measureInterval = 200 * time.Millisecond
	measureCount    = 100

	measureTTL  = 64
	measureWait = 2 * time.Second
)

const (
	fallbackHost = "speed.cloudflare.com"
	fallbackPort = 443
)

type vpnMeasureParams struct {
	Target string `json:"target"`
}

type measureRun struct {
	mu      sync.Mutex
	running bool
	result  map[string]any
	err     string
	at      time.Time
}

var measureState measureRun

func (v *vpnApplier) vpnMeasure(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p vpnMeasureParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalidParams()
		}
	}
	measureState.mu.Lock()
	if measureState.running {
		measureState.mu.Unlock()
		return map[string]any{"running": true}, nil
	}
	measureState.running = true
	measureState.result = nil
	measureState.err = ""
	measureState.at = time.Now()
	measureState.mu.Unlock()

	go func() {

		t0 := time.Now()
		log.Printf("vpn: path measurement started")
		res, aerr := v.runMeasure(p.Target)
		if aerr != nil {
			log.Printf("vpn: path measurement failed after %s: %s", time.Since(t0).Round(time.Second), aerr.Message)
		} else {
			log.Printf("vpn: path measurement finished in %s", time.Since(t0).Round(time.Second))
		}
		measureState.mu.Lock()
		measureState.running = false
		measureState.result = res
		if aerr != nil {
			measureState.err = aerr.Message
		}
		measureState.mu.Unlock()
	}()
	return map[string]any{"running": true, "started": true}, nil
}

func (v *vpnApplier) vpnMeasureStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	measureState.mu.Lock()
	defer measureState.mu.Unlock()
	out := map[string]any{"running": measureState.running}
	if measureState.err != "" {
		out["err"] = measureState.err
	}
	for k, val := range measureState.result {
		out[k] = val
	}
	return out, nil
}

func (v *vpnApplier) runMeasure(wantTarget string) (map[string]any, *agentrpc.ErrorObject) {
	st := v.readState()
	target, aerr := v.resolveProbeTarget(&st, wantTarget)
	if aerr != nil {
		return nil, aerr
	}
	endpoint := net.ParseIP(st.EndpointIP)
	if endpoint == nil {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "адрес сервера подключения неизвестен — включите защищённый канал и повторите",
			Data:    map[string]any{"recoverable": true}}
	}

	mark := currentTunnelFwmark()
	iface := v.iface(&st)
	res := map[string]any{}
	var mu sync.Mutex
	set := func(key string, stats vpncheck.Stats, err error) {
		mu.Lock()
		defer mu.Unlock()
		item := map[string]any{"stats": stats}
		if err != nil {
			item["err"] = "измерить не удалось: " + err.Error()
		}
		res[key] = item
	}

	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		s, err := icmpProbe(endpoint, measureCount, measureTTL, mark)
		set("direct_leg", s, err)
	}()
	go func() {
		defer wg.Done()

		peer, refusal := tunnelLegTarget(v.driver(&st).facts(), iface)
		if refusal != "" {
			set("tunnel_leg", vpncheck.Stats{}, errors.New(refusal))
			return
		}
		s, err := icmpProbe(peer, measureCount, measureTTL, 0)
		set("tunnel_leg", s, err)
	}()
	go func() {
		defer wg.Done()
		s, err := icmpProbe(target, measureCount, measureTTL, 0)
		set("service", s, err)
	}()
	go func() {
		defer wg.Done()

		s, err := largeProbe(target, iface)
		set("large", s, err)
	}()
	go func() {
		defer wg.Done()
		s, fallback, err := connectProbe(target, measureCount)
		mu.Lock()
		item := map[string]any{"stats": s, "fallback": fallback}
		if err != nil {
			item["err"] = "измерить не удалось: " + err.Error()
		}
		res["data"] = item
		mu.Unlock()
	}()
	wg.Wait()

	load1, cores := loadAverage()
	res["cores"] = cores
	res["load1"] = load1
	res["target"] = target.String()
	return res, nil
}

func largeProbe(target net.IP, iface string) (vpncheck.Stats, error) {
	mtu := readIfaceMTU(iface)
	if mtu <= 0 {
		return vpncheck.Stats{}, fmt.Errorf("размер пакетов канала неизвестен")
	}

	payload := mtu - 28
	if payload < 100 {
		return vpncheck.Stats{}, fmt.Errorf("размер пакетов канала слишком мал для проверки")
	}
	return icmpProbeSized(target, largeProbeCount, 64, 0, payload, true)
}

const largeProbeCount = 10

func tunnelLegTarget(f tunnelFacts, iface string) (net.IP, string) {
	if f.PeerIPv4 == "" {
		return nil, "дальний конец канала не назвал свой адрес внутри канала — плечо внутри канала измерить нельзя"
	}
	peer := net.ParseIP(f.PeerIPv4)
	if peer == nil || peer.To4() == nil {
		return nil, "дальний конец канала назвал адрес, который не является адресом сети — плечо внутри канала измерить нельзя"
	}

	if !routedThroughTunnel(peer, iface) {
		return nil, "путь до дальнего конца проходит мимо канала — плечо внутри канала измерить нельзя"
	}
	return peer, ""
}

func routedThroughTunnel(ip net.IP, iface string) bool {
	bin, err := findBinary(ipCandidates)
	if err != nil {
		return true
	}
	out, err := exec.Command(bin, "route", "get", ip.String()).Output() //nolint:gosec
	if err != nil {
		return true
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1] == iface
		}
	}
	return true
}

func (v *vpnApplier) resolveProbeTarget(st *vpnState, want string) (net.IP, *agentrpc.ErrorObject) {
	allowed := map[string]bool{}
	for _, a := range st.Black.DNS.Forwarders {
		allowed[a] = true
	}
	for _, a := range unboundgen.Upstream {
		allowed[a] = true
	}
	if want == "" {
		if len(st.Black.DNS.Forwarders) > 0 {
			want = st.Black.DNS.Forwarders[0]
		} else {
			want = unboundgen.Upstream[0]
		}
	}
	ip := net.ParseIP(want)
	if ip == nil || ip.To4() == nil || !allowed[want] {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "цель проверки не входит в список серверов имён панели",
			Data:    map[string]any{"recoverable": false}}
	}
	return ip, nil
}

func icmpProbe(target net.IP, count, ttl, mark int) (vpncheck.Stats, error) {
	return icmpProbeSized(target, count, ttl, mark, measurePayload, false)
}

func icmpProbeSized(target net.IP, count, ttl, mark, payload int, noFragment bool) (vpncheck.Stats, error) {

	if count > 0xffff {
		count = 0xffff
	}
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return vpncheck.Stats{}, fmt.Errorf("нет прав на служебные пакеты: %w", err)
	}
	defer func() { _ = conn.Close() }()

	raw, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return vpncheck.Stats{}, fmt.Errorf("сокет не поддерживает настройку")
	}
	sc, err := raw.SyscallConn()
	if err != nil {
		return vpncheck.Stats{}, err
	}
	var setErr error
	if cerr := sc.Control(func(fd uintptr) {

		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
			setErr = err
			return
		}
		if mark > 0 {
			if setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); setErr != nil {
				return
			}
		}
		if noFragment {

			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 10, 2)
		}
	}); cerr != nil {
		return vpncheck.Stats{}, cerr
	}
	if setErr != nil {
		return vpncheck.Stats{}, setErr
	}

	id := uint16(time.Now().UnixNano() & 0xffff)
	dst := &net.IPAddr{IP: target}
	sentAt := make(map[uint16]time.Time, count)
	var mu sync.Mutex
	var rtts []time.Duration

	got := make(map[int]bool, count)

	stop := readReplies(conn, id, measureWait, func(seq uint16) {
		mu.Lock()
		if t0, okSeq := sentAt[seq]; okSeq {
			rtts = append(rtts, time.Since(t0))
			got[int(seq)] = true
			delete(sentAt, seq)
		}
		mu.Unlock()
	})

	sent := 0
	ticker := time.NewTicker(measureInterval)
	defer ticker.Stop()
	for seq := 0; seq < count; seq++ {
		msg := vpncheck.EchoRequest(id, uint16(seq), payload)
		mu.Lock()
		sentAt[uint16(seq)] = time.Now()
		mu.Unlock()
		if _, werr := conn.WriteTo(msg, dst); werr != nil {
			mu.Lock()
			delete(sentAt, uint16(seq))
			mu.Unlock()
			continue
		}
		sent++
		<-ticker.C
	}

	time.Sleep(measureWait)
	stop()

	mu.Lock()
	defer mu.Unlock()
	if sent == 0 {
		return vpncheck.Stats{}, fmt.Errorf("ни один служебный пакет не удалось отправить")
	}
	stats := vpncheck.Summarize(sent, rtts)
	stats.MaxBurst, stats.BurstEvents = vpncheck.Bursts(sent, got)
	return stats, nil
}

type replyConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	SetReadDeadline(time.Time) error
	Close() error
}

func readReplies(conn replyConn, id uint16, wait time.Duration, onReply func(seq uint16)) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(wait))
			n, _, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			kind, seq, perr := vpncheck.ParseReply(buf[:n], id)
			if perr != nil || (kind != vpncheck.ReplyEcho && kind != vpncheck.ReplyExpired) {
				continue
			}
			onReply(seq)
		}
	}()

	return func() {
		_ = conn.Close()
		<-done
	}
}

func connectProbe(target net.IP, count int) (vpncheck.Stats, bool, error) {
	addr := net.JoinHostPort(target.String(), "53")

	got := map[int]bool{}
	probeRTTs, refusedFast := dialSeries(addr, 0, 10, nil, got)
	if refusedFast {
		fb, err := net.LookupHost(fallbackHost)
		if err != nil || len(fb) == 0 {
			return withBursts(10, probeRTTs, got), false,
				fmt.Errorf("порт 53 закрыт для соединений, запасная цель не разрешилась")
		}
		fbGot := map[int]bool{}
		rtts, _ := dialSeries(net.JoinHostPort(fb[0], fmt.Sprint(fallbackPort)), 0, count, nil, fbGot)
		return withBursts(count, rtts, fbGot), true, nil
	}
	rtts, _ := dialSeries(addr, 10, count-10, probeRTTs, got)
	return withBursts(count, rtts, got), false, nil
}

func withBursts(sent int, rtts []time.Duration, got map[int]bool) vpncheck.Stats {
	stats := vpncheck.Summarize(sent, rtts)
	stats.MaxBurst, stats.BurstEvents = vpncheck.Bursts(sent, got)
	return stats
}

func dialSeries(addr string, start, count int, rtts []time.Duration, got map[int]bool) ([]time.Duration, bool) {
	refusedFast := 0
	ticker := time.NewTicker(measureInterval)
	defer ticker.Stop()
	for i := 0; i < count; i++ {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", addr, measureWait)
		took := time.Since(t0)
		if err == nil {
			rtts = append(rtts, took)
			got[start+i] = true
			_ = conn.Close()
		} else if took < 100*time.Millisecond {
			refusedFast++
		}
		<-ticker.C
	}
	return rtts, count > 0 && refusedFast*2 > count
}
