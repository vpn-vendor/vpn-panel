package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	surroundEvery = time.Minute

	bootSettleMax = 5 * time.Minute

	surroundShare = 20

	settleSkipsMax = 2

	codeDHCPForeign = 1205
	codeLegacyBusy  = 2403
)

type surroundEnv struct {
	root  string
	units func(unit string) svcState

	unitsKnown bool

	awaiting func() bool

	skip func(unit string) bool

	residue func() []string
}

func (env surroundEnv) legacyGateway() bool {
	return env.legacyReport(nil).Gateway
}

func (env surroundEnv) legacyReport(units legacyvpn.UnitState) legacyvpn.Report {
	r := legacyvpn.Detect(env.root, units)
	if env.residue != nil {
		r = r.Without(env.residue())
	}
	return r
}

type svcState struct {
	Enabled, Active bool

	Moving bool
}

type observation struct {
	hostcaps.Fact
	moving, hold bool
}

func seen(fs ...hostcaps.Fact) []observation {
	out := make([]observation, 0, len(fs))
	for _, f := range fs {
		out = append(out, observation{Fact: f})
	}
	return out
}

type surroundProbe struct {
	ids []string
	run func(ctx context.Context, env surroundEnv) []observation
}

type surroundings struct {
	mu      sync.Mutex
	snap    atomic.Pointer[hostcaps.Surroundings]
	limiter *ratelimit.Limiter
	kick    chan struct{}

	probes []surroundProbe

	resetters  map[string]func()
	env        surroundEnv
	queryUnits func() (map[string]svcState, bool)
	booted     func() bool
	now        func() time.Time

	last      map[string]hostcaps.Fact
	skips     map[string]int
	published map[string]hostcaps.Fact

	takeover *takeoverRunner
}

func (s *surroundings) useTakeover(r *takeoverRunner) {
	s.takeover = r
	s.env.residue = r.residue
	doomed := r.doomed
	s.env.skip = func(unit string) bool { return slices.Contains(doomed(), strings.TrimSuffix(unit, ".service")) }
}

func newSurroundings(awaiting func() bool) *surroundings {
	s := &surroundings{

		limiter:    ratelimit.New(2, 1, 30*time.Second),
		kick:       make(chan struct{}, 1),
		probes:     surroundProbeSet(),
		env:        surroundEnv{root: "/", awaiting: awaiting},
		queryUnits: func() (map[string]svcState, bool) { return svcStates(surroundUnits()) },
		booted:     systemBooted,
		now:        time.Now,
		last:       map[string]hostcaps.Fact{},
		skips:      map[string]int{},
		published:  map[string]hostcaps.Fact{},
	}
	s.snap.Store(&hostcaps.Surroundings{Settling: true, Facts: []hostcaps.Fact{}})
	return s
}

func (s *surroundings) start() {
	go func() {
		started := s.now()
		for !s.booted() && s.now().Sub(started) < bootSettleMax {
			time.Sleep(surroundEvery / surroundShare)
		}
		kicked := false
		for {
			began := s.now()
			pending := s.step()
			pause := surroundEvery

			if spent := s.now().Sub(began) * surroundShare; spent > pause {
				pause = spent
			}

			if kicked && pending {
				pause = surroundEvery / surroundShare
			}
			select {
			case <-s.kick:
				kicked = true
			case <-time.After(pause):
				kicked = false
			}
		}
	}()
}

func (s *surroundings) kickSoon() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *surroundings) step() (pending bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), surroundEvery)
	defer cancel()
	env := s.env
	units, known := s.queryUnits()
	env.units, env.unitsKnown = func(u string) svcState { return units[u] }, known
	settling := false
	for _, p := range s.probes {
		for _, o := range p.run(ctx, env) {
			f := o.Fact
			_, public := s.published[f.ID]
			if o.hold {
				settling = settling || !public
				continue
			}
			if o.moving {

				if s.skips[f.ID] < settleSkipsMax || f.Answer == hostcaps.Unknown {
					if s.skips[f.ID] < settleSkipsMax {
						s.skips[f.ID]++
					}
					settling = settling || !public
					continue
				}
			} else {
				s.skips[f.ID] = 0
			}
			prev, was := s.last[f.ID]
			s.last[f.ID] = f
			switch {
			case was && sameObservation(prev, f):
				s.published[f.ID] = f
			case !public:
				settling = true
			}
			if pub, ok := s.published[f.ID]; !ok || !sameObservation(pub, f) {
				pending = true
			}
		}
	}
	facts := make([]hostcaps.Fact, 0, len(s.published))
	for _, f := range s.published {
		facts = append(facts, f)
	}
	sort.Slice(facts, func(a, b int) bool { return facts[a].ID < facts[b].ID })
	s.snap.Store(&hostcaps.Surroundings{TakenAt: s.now().UTC().Format(time.RFC3339),
		Settling: settling, Facts: facts})
	return pending
}

func sameObservation(a, b hostcaps.Fact) bool {
	return a.Answer == b.Answer && a.Value == b.Value && a.Level == b.Level &&
		strings.Join(a.Cards, ",") == strings.Join(b.Cards, ",")
}

func (s *surroundings) surroundingsStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	return *s.snap.Load(), nil
}

func (s *surroundings) surroundingsRescan(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		Reset []string `json:"reset"`
	}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
				Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку",
				Data:    map[string]any{"recoverable": false}}
		}
	}
	if !s.limiter.Allow("rescan") {
		return nil, agentrpc.Busy(codeHostBusy, "проверка запрошена слишком часто — подождите",
			s.limiter.RetryIn("rescan"))
	}
	reset := 0
	for _, id := range p.Reset {

		if r, ok := s.resetters[id]; ok && !devmode.Enabled {
			r()
			reset++
		}
	}
	s.kickSoon()
	return map[string]any{"started": true, "reset": reset}, nil
}

func (s *surroundings) afterApply(h agentrpc.Handler) agentrpc.Handler {
	return func(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
		res, err := h(raw)
		if err == nil {
			s.kickSoon()
		}
		return res, err
	}
}

func systemBooted() bool {
	bin, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return true
	}
	out, _ := exec.Command(bin, "is-system-running").Output() //nolint:gosec
	switch strings.TrimSpace(string(out)) {
	case "initializing", "starting":
		return false
	}
	return true
}

func svcStates(names []string) (map[string]svcState, bool) {
	bin, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return map[string]svcState{}, false
	}
	args := append([]string{"show", "-p", "Id", "-p", "UnitFileState", "-p", "ActiveState", "-p", "SubState", "--"}, names...)
	out, err := exec.Command(bin, args...).Output() //nolint:gosec
	if err != nil {
		return map[string]svcState{}, false
	}
	return parseSvcStates(string(out)), true
}

func parseSvcStates(out string) map[string]svcState {
	res := map[string]svcState{}
	for _, block := range strings.Split(out, "\n\n") {
		id := ""
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Id="); ok {
				id = v
			}
		}
		if id != "" {
			res[strings.TrimSuffix(id, ".service")] = parseSvcState(block)
		}
	}
	return res
}

func parseSvcState(out string) svcState {
	var st svcState
	var active, sub string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "UnitFileState":
			st.Enabled = v == "enabled" || v == "enabled-runtime" || v == "generated"
		case "ActiveState":
			active = v
		case "SubState":
			sub = v
		}
	}
	st.Active = active == "active" || active == "reloading"
	st.Moving = (active == "activating" || active == "deactivating") && sub != "auto-restart"
	return st
}
