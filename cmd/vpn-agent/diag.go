package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagfacts"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	codeDiagBusy     = 1501
	codeDiagNoCard   = 1502
	codeDiagNoLAN    = 1503
	codeDiagLoad     = 1504
	codeDiagRunning  = 1505
	codeDiagNoDevice = 1506
)

type diagApplier struct {
	mu      sync.Mutex
	limiter *ratelimit.Limiter
	running bool
}

const (
	probeCount       = 5
	probeCountSingle = 3
	probeDeadlineSec = 6
	probeParallel    = 16
	probeTimeout     = 45 * time.Second
	probeMaxTargets  = 256
)

func newDiagApplier() *diagApplier {

	return &diagApplier{limiter: ratelimit.New(1, 1, time.Minute)}
}

var lanNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

type diagParams struct {
	LANs   []string `json:"lans"`
	Target string   `json:"target,omitempty"`
}

func knownLANs(names []string) ([]string, *netstatus.Status, *agentrpc.ErrorObject) {
	status, err := netstatus.Collect()
	if err != nil {
		return nil, nil, internalErr(errReadInterfaces, true)
	}
	known := map[string]bool{}
	for _, i := range status.Interfaces {
		if !i.Loopback {
			known[i.Name] = true
		}
	}
	var out []string
	for _, n := range names {

		if !lanNameRe.MatchString(n) || !known[n] {
			return nil, nil, &agentrpc.ErrorObject{Code: codeDiagNoCard,
				Message: "карта локальной сети «" + n + "» не найдена — обновите страницу",
				Data:    map[string]any{"recoverable": false}}
		}
		out = append(out, n)
	}
	return out, status, nil
}

func (d *diagApplier) diagFacts(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p diagParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
				Message: "запрос к системной службе составлен неверно — обновите страницу", Data: map[string]any{"recoverable": false}}
		}
	}
	lans, _, rerr := knownLANs(p.LANs)
	if rerr != nil {
		return nil, rerr
	}
	ipBin, err := findBinary([]string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"})
	if err != nil {
		return nil, internalErr(errToolMissing, false)
	}
	facts := diagfacts.Facts{Sets: map[string][]diagfacts.SetEntry{}, UptimeSec: uptimeSeconds()}

	for _, lan := range lans {
		out, err := exec.Command(ipBin, "-json", "neigh", "show", "dev", lan).Output() //nolint:gosec
		if err == nil {
			if n, perr := diagfacts.ParseNeighbours(out); perr == nil {
				facts.Neighbours = append(facts.Neighbours, diagfacts.WithDev(n, lan)...)
			}
		}
		if ls, ok := readLink(ipBin, lan); ok {
			facts.Links = append(facts.Links, ls)
		}
	}

	if nft, err := findBinary(nftCandidates); err == nil {
		for _, name := range nftgen.DiagSets {
			out, err := exec.Command(nft, "-j", "list", "set", "inet", "vpn_panel", name).Output() //nolint:gosec
			if err != nil {
				continue
			}
			if entries, perr := diagfacts.ParseSet(out); perr == nil {
				facts.Sets[name] = entries
			}
		}
	}
	return facts, nil
}

func readLink(ipBin, name string) (diagfacts.LinkStats, bool) {
	out, err := exec.Command(ipBin, "-s", "-json", "link", "show", "dev", name).Output() //nolint:gosec
	if err != nil {
		return diagfacts.LinkStats{}, false
	}
	speed, _ := os.ReadFile("/sys/class/net/" + name + "/speed")   //nolint:gosec
	duplex, _ := os.ReadFile("/sys/class/net/" + name + "/duplex") //nolint:gosec
	ls, perr := diagfacts.ParseLink(out, string(speed), string(duplex))
	return ls, perr == nil
}

func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return int64(v)
}

func (d *diagApplier) diagProbe(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p diagParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу", Data: map[string]any{"recoverable": false}}
	}
	lans, status, rerr := knownLANs(p.LANs)
	if rerr != nil {
		return nil, rerr
	}
	if len(lans) == 0 {
		return nil, &agentrpc.ErrorObject{Code: codeDiagNoLAN,
			Message: "нет карт с ролью «локальная сеть» — назначьте роли на странице «Сеть»",
			Data:    map[string]any{"recoverable": false}}
	}
	if !d.limiter.Allow("probe") {
		return nil, agentrpc.Busy(codeDiagBusy, "проверка сети запускалась меньше минуты назад — подождите", d.limiter.RetryIn("probe"))
	}
	if load1, cores := loadAverage(); load1 > float64(cores) {
		return nil, &agentrpc.ErrorObject{Code: codeDiagLoad,
			Message: "сервер сейчас сильно загружен — повторите проверку через несколько минут",
			Data:    map[string]any{"recoverable": true}}
	}

	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return nil, &agentrpc.ErrorObject{Code: codeDiagRunning,
			Message: "проверка сети уже идёт — дождитесь результата",
			Data:    map[string]any{"recoverable": true}}
	}
	d.running = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.running = false; d.mu.Unlock() }()

	arping, err := findBinary([]string{"/usr/sbin/arping", "/usr/bin/arping", "/sbin/arping"})
	if err != nil {
		return nil, internalErr("инструмент проверки сети не установлен — переустановите пакет или обратитесь в поддержку", false)
	}
	ipBin, err := findBinary([]string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"})
	if err != nil {
		return nil, internalErr(errToolMissing, false)
	}

	subnets := map[string][]*net.IPNet{}
	for _, iface := range status.Interfaces {
		for _, cidr := range iface.Addresses {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.IP.To4() != nil {
				subnets[iface.Name] = append(subnets[iface.Name], ipnet)
			}
		}
	}
	type target struct{ ip, dev string }
	var targets []target
	for _, lan := range lans {
		out, err := exec.Command(ipBin, "-json", "neigh", "show", "dev", lan).Output() //nolint:gosec
		if err != nil {
			continue
		}
		neigh, perr := diagfacts.ParseNeighbours(out)
		if perr != nil {
			continue
		}
		neigh = diagfacts.WithDev(neigh, lan)
		for _, n := range neigh {
			ip := net.ParseIP(n.IP)
			if ip == nil || !inSubnets(ip, subnets[lan]) {
				continue
			}
			if p.Target != "" && n.IP != p.Target {
				continue
			}
			targets = append(targets, target{ip: n.IP, dev: lan})
		}
	}
	if p.Target != "" && len(targets) == 0 {
		return nil, &agentrpc.ErrorObject{Code: codeDiagNoDevice,
			Message: "устройство не найдено среди известных соседей шлюза — проверьте, что оно подключено к локальной сети",
			Data:    map[string]any{"recoverable": true}}
	}
	if len(targets) > probeMaxTargets {
		targets = targets[:probeMaxTargets]
	}

	count, deadline := probeCount, probeDeadlineSec
	if p.Target != "" {
		count, deadline = probeCountSingle, probeCountSingle+1
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	results := make([]diagfacts.ProbeResult, len(targets))
	sem := make(chan struct{}, probeParallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t target) {
			defer wg.Done()
			defer func() { <-sem }()

			cmd := exec.CommandContext(ctx, arping, "-c", strconv.Itoa(count), "-w", strconv.Itoa(deadline), "-I", t.dev, t.ip) //nolint:gosec
			out, _ := cmd.CombinedOutput()
			results[i] = diagfacts.ParseArping(t.ip, out)
		}(i, t)
	}
	wg.Wait()
	if ctx.Err() != nil {
		log.Printf("diag: probe hit the hard deadline (%s)", probeTimeout)
	}
	return map[string]any{"results": results, "started_at": time.Now().Unix(), "deadline_hit": ctx.Err() != nil}, nil
}

func inSubnets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func loadAverage() (float64, int) {
	cores := runtime.NumCPU()
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, cores
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, cores
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v, cores
}
