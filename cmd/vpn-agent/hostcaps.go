package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

const (
	hostCacheDir  = "/var/cache/vpn-panel"
	hostCacheFile = hostCacheDir + "/host-passport.json"
)

const (
	hostProbeDeadline = time.Minute
	hostCheckTimeout  = 20 * time.Second
)

const codeHostBusy = 2401

type hostCapsSource interface {
	current() hostcaps.Snapshot

	recheck(used string) bool
}

func capsOf(src hostCapsSource) hostcaps.Snapshot {
	if src == nil {
		return hostcaps.Snapshot{}
	}
	return src.current()
}

type hostProbe struct {
	ids      []string
	packages []string
	run      func(ctx context.Context) []hostcaps.Fact
}

type hostProbeOwner interface{ hostProbes() []hostProbe }

type hostCapsTaker interface{ useHostCaps(hostCapsSource) }

type hostPassport struct {
	mu      sync.Mutex
	snap    atomic.Pointer[hostcaps.Snapshot]
	probing atomic.Bool
	limiter *ratelimit.Limiter

	versions func(packages []string) map[string]string
	probes   []hostProbe
	readFile func() ([]byte, error)
	write    func([]byte) error
	now      func() time.Time

	onChange func()
}

func newHostPassport() *hostPassport {
	return &hostPassport{

		limiter:  ratelimit.New(2, 1, 30*time.Second),
		versions: hostVersions,
		probes:   hostProbeSet(),
		readFile: func() ([]byte, error) { return os.ReadFile(hostCacheFile) },
		write: func(b []byte) error {
			if err := durable.MkdirAll(hostCacheDir, 0o755); err != nil {
				return err
			}
			return durable.Write(hostCacheFile, b, 0o644)
		},
		now: time.Now,
	}
}

func (h *hostPassport) start() {
	h.loadCache()
	if h.stale() {
		go h.probeNow()
	}
}

func (h *hostPassport) loadCache() {
	raw, err := h.readFile()
	if err != nil {
		return
	}
	var s hostcaps.Snapshot
	if json.Unmarshal(raw, &s) == nil && s.Schema == hostcaps.Schema {
		h.snap.Store(&s)
	}
}

func (h *hostPassport) current() hostcaps.Snapshot {
	if s := h.snap.Load(); s != nil {
		return *s
	}
	return hostcaps.Snapshot{}
}

func (h *hostPassport) inputs() (map[string]string, string) {
	var ids, packages []string
	for _, p := range h.probes {
		ids = append(ids, p.ids...)
		packages = append(packages, p.packages...)
	}
	versions := h.versions(packages)
	return versions, hostcaps.InputsDigest(versions, ids)
}

func (h *hostPassport) stale() bool {
	_, key := h.inputs()
	s := h.current()
	return s.Inputs != key || s.Unsure()
}

func (h *hostPassport) probeNow() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.probing.Store(true)
	defer h.probing.Store(false)

	versions, key := h.inputs()
	log.Printf("host: probing the system")
	ctx, cancel := context.WithTimeout(context.Background(), hostProbeDeadline)
	defer cancel()
	var facts []hostcaps.Fact
	for _, p := range h.probes {
		facts = append(facts, p.run(ctx)...)
	}
	sort.Slice(facts, func(a, b int) bool { return facts[a].ID < facts[b].ID })

	s := hostcaps.Snapshot{Schema: hostcaps.Schema, TakenAt: h.now().UTC().Format(time.RFC3339),
		Inputs: key, Digest: hostcaps.FactsDigest(facts), Versions: versions, Facts: facts}
	prev := h.current()
	h.snap.Store(&s)
	if raw, err := json.MarshalIndent(s, "", "  "); err == nil {
		if err := h.write(append(raw, '\n')); err != nil {
			log.Printf("host: passport not saved: %v", err)
		}
	}
	if prev.Digest != s.Digest {
		log.Printf("host: passport changed: %s", factLine(facts))
		if h.onChange != nil {
			go h.onChange()
		}
	} else {
		log.Printf("host: passport unchanged")
	}
	return s.Digest
}

func (h *hostPassport) recheck(used string) bool {
	h.mu.Lock()
	cur := h.current().Digest
	h.mu.Unlock()
	if cur != used {
		return true
	}
	if !h.limiter.Allow("recheck") {
		return false
	}
	return h.probeNow() != used
}

func (h *hostPassport) passportStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	s := h.current()
	if s.Facts == nil {
		s.Facts = []hostcaps.Fact{}
	}
	if s.Versions == nil {
		s.Versions = map[string]string{}
	}
	return hostcaps.Status{Snapshot: s, Probing: h.probing.Load()}, nil
}

func (h *hostPassport) passportRefresh(json.RawMessage) (any, *agentrpc.ErrorObject) {
	if !h.limiter.Allow("refresh") {
		return nil, agentrpc.Busy(codeHostBusy, "проверка возможностей системы запрошена слишком часто — подождите",
			h.limiter.RetryIn("refresh"))
	}
	if h.probing.Load() || !h.stale() {
		return map[string]any{"started": false}, nil
	}
	go h.probeNow()
	return map[string]any{"started": true}, nil
}

func (v *vpnApplier) useHostCaps(h *hostPassport) {
	for _, d := range v.drivers {
		if o, ok := d.(hostProbeOwner); ok {
			h.probes = append(h.probes, o.hostProbes()...)
		}
		if t, ok := d.(hostCapsTaker); ok {
			t.useHostCaps(h)
		}
	}
}

func hostVersions(packages []string) map[string]string {
	v := map[string]string{}
	args := append([]string{"-W", "-f=${Package}\t${db:Status-Status}\t${Version}\n"}, packages...)

	out, _ := exec.Command("dpkg-query", args...).Output() //nolint:gosec
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Split(line, "\t"); len(f) == 3 && f[1] == "installed" {
			v[f[0]] = f[2]
		}
	}

	if out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "vpn-panel").Output(); err == nil { //nolint:gosec
		v["vpn-panel"] = strings.TrimSpace(string(out))
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		v["kernel"] = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile("/etc/os-release"); err == nil {
		v["os"] = sysinfo.ParseOSField(raw, "VERSION_ID") + " " + sysinfo.ParseOSField(raw, "VERSION_CODENAME")
	}
	return v
}

func factLine(facts []hostcaps.Fact) string {
	parts := make([]string, 0, len(facts))
	for _, f := range facts {
		p := f.ID + "=" + string(f.Answer)
		if f.Value != "" {
			p += "(" + f.Value + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}
