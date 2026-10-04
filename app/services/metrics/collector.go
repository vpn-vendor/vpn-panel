package metrics

import (
	"bytes"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/metrics"
	"github.com/vpn-vendor/vpn-panel-core/internal/procstat"
)

const (
	Tick            = time.Second
	BudgetShare     = 10
	AnomalyFactor   = 10
	AnomalyFloor    = time.Millisecond
	BaselineSamples = 32
	BaselineMin     = 8
	FuseStrikes     = 3
	FusePauseMin    = 5 * time.Minute
	FusePauseMax    = time.Hour
	ProtectWindow   = 10
	ProtectStale    = 10 * time.Second
	SaveEvery       = 5 * time.Minute
	FileName        = "metrics.bin"
	SettingMaster   = "metrics.master"
	SettingSource   = "metrics.source."
)

type Store interface {
	Get(key string) string
	Set(key, value string) error
}

type fuse struct {
	strikes int
	pauses  int
	trial   bool
	base    [BaselineSamples]time.Duration
	baseN   int
	baseAt  int
}

func (f *fuse) sample(d time.Duration) {
	f.base[f.baseAt] = d
	f.baseAt = (f.baseAt + 1) % BaselineSamples
	if f.baseN < BaselineSamples {
		f.baseN++
	}
}

func (f *fuse) median() time.Duration {
	if f.baseN < BaselineMin {
		return 0
	}
	vals := make([]time.Duration, f.baseN)
	copy(vals, f.base[:f.baseN])
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return vals[f.baseN/2]
}

func (c *Collector) limit(f *fuse) time.Duration {
	abs := c.tick / BudgetShare
	if m := f.median(); m > 0 {
		th := m * AnomalyFactor
		if th < AnomalyFloor {
			th = AnomalyFloor
		}
		if th < abs {
			return th
		}
	}
	return abs
}

type Protect struct {
	CPUBusy     float64
	PressureCPU float64
	LANSpeed    float64
	OK          bool
}

type Collector struct {
	mu       sync.Mutex
	sources  []Source
	rows     map[string]*metrics.Series
	store    Store
	now      func() time.Time
	lanName  func() string
	fuses    map[string]*fuse
	states   map[string]State
	master   State
	cacheAt  time.Time
	reads    map[string]uint64
	cost     map[string]time.Duration
	notices  map[string]string
	dataDir  string
	lastSave time.Time
	record   func(models.AuthEvent)
	tick     time.Duration
	cpu      cpuReader
	prot     [ProtectWindow]struct {
		at        time.Time
		busy, psi float64
		busyOK    bool
	}
	protHead int
	lanSpeed float64
}

var (
	oneMu sync.Mutex
	one   *Collector
)

func New(sources []Source, store Store, dataDir string, lanName func() string) *Collector {
	c := &Collector{sources: sources, rows: map[string]*metrics.Series{}, store: store, now: time.Now,
		lanName: lanName, fuses: map[string]*fuse{}, states: map[string]State{},
		reads: map[string]uint64{}, cost: map[string]time.Duration{}, notices: map[string]string{}, dataDir: dataDir,
		record: securitylog.Record, tick: Tick}
	for _, s := range sources {
		c.fuses[s.Name] = &fuse{}
		for _, r := range s.Rows {
			c.rows[r] = metrics.New()
		}
	}
	return c
}

func Current() *Collector {
	oneMu.Lock()
	defer oneMu.Unlock()
	return one
}

func setCurrent(c *Collector) {
	oneMu.Lock()
	one = c
	oneMu.Unlock()
}

func (c *Collector) refreshStates(now time.Time, force bool) {
	if !force && !c.cacheAt.IsZero() && now.Sub(c.cacheAt) < 10*time.Second {
		return
	}
	c.cacheAt = now
	c.master = Parse(c.store.Get(SettingMaster))
	for _, s := range c.sources {
		c.states[s.Name] = Parse(c.store.Get(SettingSource + s.Name))
	}
}

func (c *Collector) Effective(name string) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.refreshStates(now, false)
	return Combine(c.master, c.states[name], now)
}

func (c *Collector) Master() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshStates(c.now(), false)
	return c.master.Now(c.now())
}

func (c *Collector) SetMaster(st State, ip string) error {
	if err := c.store.Set(SettingMaster, st.String()); err != nil {
		return err
	}
	c.mu.Lock()
	c.refreshStates(c.now(), true)
	c.mu.Unlock()
	c.record(models.AuthEvent{Event: "metrics_master", IP: ip, OccurredAt: c.now(), Details: "рубильник сбора: " + describe(st)})
	return nil
}

func (c *Collector) SetSource(name string, st State, ip string) error {
	if _, ok := c.fuses[name]; !ok {
		return ErrUnknownSource
	}
	if err := c.store.Set(SettingSource+name, st.String()); err != nil {
		return err
	}
	c.mu.Lock()
	c.refreshStates(c.now(), true)
	if st.Mode == On {
		c.fuses[name] = &fuse{}
		delete(c.notices, name)
	}
	c.mu.Unlock()
	c.record(models.AuthEvent{Event: "metrics_source", IP: ip, OccurredAt: c.now(), Details: name + ": " + describe(st)})
	return nil
}

func describe(st State) string {
	if st.Mode == Paused {
		return "пауза до " + st.Until.Local().Format("02.01.2006 15:04")
	}
	return st.Mode.String()
}

func (c *Collector) Tick(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshStates(now, false)
	c.tickProtect(now)
	for i := range c.sources {
		s := &c.sources[i]
		st := Combine(c.master, c.states[s.Name], now)
		if !st.Collects() {
			continue
		}
		f := c.fuses[s.Name]
		limit := c.limit(f)
		t0 := time.Now()
		vals, err := s.Read()
		took := time.Since(t0)
		c.reads[s.Name]++
		c.cost[s.Name] = took
		if err != nil || took > limit {
			c.strike(s, f, now, err, took, limit)
			continue
		}
		f.sample(took)
		f.strikes = 0
		if f.trial {
			f.trial, f.pauses = false, 0
			delete(c.notices, s.Name)
		}
		for _, r := range s.Rows {
			v, ok := vals[r]
			if !ok {
				v = math.NaN()
			}
			c.rows[r].Add(now, v)
		}
	}
}

func (c *Collector) strike(s *Source, f *fuse, now time.Time, err error, took, limit time.Duration) {
	f.strikes++
	if f.strikes < FuseStrikes && !f.trial {
		return
	}
	pause := FusePauseMin << f.pauses
	if pause > FusePauseMax {
		pause = FusePauseMax
	}
	f.pauses++
	f.strikes, f.trial = 0, true
	until := now.Add(pause)
	_ = c.store.Set(SettingSource+s.Name, State{Mode: Paused, Until: until}.String())
	c.states[s.Name] = State{Mode: Paused, Until: until}
	why := "чтение дороже порога (" + took.Round(time.Microsecond).String() + " > " + limit.Round(time.Microsecond).String() + ")"
	if err != nil {
		why = "ошибка чтения: " + err.Error()
	}
	c.notices[s.Name] = "Источник показателей «" + s.Title + "» приостановлен до " + until.Local().Format("15:04") + ": " + why + ". Вернуть сразу можно на странице «Защита»."
	c.record(models.AuthEvent{Event: "metrics_source_paused", OccurredAt: now, Details: s.Name + ": " + why + ", до " + until.Local().Format("02.01.2006 15:04:05")})
	log.Printf("сбор показателей: источник %s на паузе до %s: %s", s.Name, until.Format(time.RFC3339), why)
}

func (c *Collector) tickProtect(now time.Time) {
	p := &c.prot[c.protHead]
	c.protHead = (c.protHead + 1) % ProtectWindow
	p.at, p.busyOK = now, false
	if cur, err := procstat.ReadCPU(); err == nil {
		if c.cpu.prev.Total != 0 {
			p.busy, p.busyOK = procstat.BusyPercent(c.cpu.prev, cur)
		}
		c.cpu.prev = cur
	}
	p.psi, _ = procstat.ReadPressureSome("cpu")
	if c.lanName != nil {
		if v, ok := procstat.ReadLinkSpeed(c.lanName()); ok {
			c.lanSpeed = v
		}
	}
}

func (c *Collector) Protection() Protect {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var sum, psi float64
	n := 0
	for _, p := range c.prot {
		if p.at.IsZero() || now.Sub(p.at) > ProtectStale || !p.busyOK {
			continue
		}
		sum += p.busy
		psi = math.Max(psi, p.psi)
		n++
	}
	if n == 0 {
		return Protect{}
	}
	return Protect{CPUBusy: sum / float64(n), PressureCPU: psi, LANSpeed: c.lanSpeed, OK: true}
}

func (c *Collector) Reads(name string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads[name]
}

func (c *Collector) Notices() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	if c.master.Now(c.now()).Mode == Off {
		out = append(out, "Сбор показателей выключен администратором насовсем: графики пусты, диагнозы отвечают «не измеряется». Включить — на странице «Защита».")
	}
	for _, s := range c.sources {
		if t, ok := c.notices[s.Name]; ok {
			out = append(out, t)
		}
	}
	return out
}

type Result struct {
	Plan metrics.Plan
	From time.Time
	Rows map[string][]metrics.Point
}

func (c *Collector) Query(rows []string, from, to time.Time, width int) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	plan := metrics.PlanFor(now, from, to, width)
	res := Result{Plan: plan, From: from, Rows: map[string][]metrics.Point{}}
	for _, r := range rows {
		if s, ok := c.rows[r]; ok {
			res.Rows[r] = s.Range(plan, from, to)
		}
	}
	return res
}

func (c *Collector) Rows() []string {
	out := make([]string, 0, len(c.rows))
	for _, s := range c.sources {
		out = append(out, s.Rows...)
	}
	return out
}

func (c *Collector) Save() error {
	c.mu.Lock()
	now := c.now()
	c.refreshStates(now, false)
	persist := map[string]*metrics.Series{}
	master := c.master.Now(now)
	for _, s := range c.sources {
		st := Combine(master, c.states[s.Name], now)
		if !s.Persist || master.Mode == Memory || st.Mode == Memory {
			continue
		}
		for _, r := range s.Rows {
			persist[r] = c.rows[r]
		}
	}
	c.lastSave = now
	c.mu.Unlock()
	if len(persist) == 0 || c.dataDir == "" {
		return nil
	}
	var buf bytes.Buffer
	c.mu.Lock()
	err := metrics.Save(&buf, persist)
	c.mu.Unlock()
	if err != nil {
		return err
	}

	return durable.Write(filepath.Join(c.dataDir, FileName), buf.Bytes(), 0o600)
}

func (c *Collector) Load() {
	if c.dataDir == "" {
		return
	}

	if n, _ := durable.Sweep(c.dataDir); n > 0 {
		log.Printf("сбор показателей: убрано недописанных временных файлов: %d", n)
	}
	f, err := os.Open(filepath.Join(c.dataDir, FileName))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	c.mu.Lock()
	n, err := metrics.Load(f, c.rows)
	c.mu.Unlock()
	if err != nil {
		log.Printf("сбор показателей: файл истории не принят (%v) — старт без истории", err)
		return
	}
	log.Printf("сбор показателей: восстановлено колец истории: %d", n)
}

type SourceView struct {
	Name      string
	Title     string
	Depends   string
	Own       State
	Effective State
	Cost      time.Duration
	Limit     time.Duration
	Reads     uint64
	Rows      []string
}

type Snapshot struct {
	Master  State
	Sources []SourceView
	Protect Protect
}

func (c *Collector) View() Snapshot {
	c.mu.Lock()
	now := c.now()
	c.refreshStates(now, false)
	out := Snapshot{Master: c.master.Now(now)}
	for _, s := range c.sources {
		own := c.states[s.Name].Now(now)
		out.Sources = append(out.Sources, SourceView{Name: s.Name, Title: s.Title, Depends: s.Depends,
			Own: own, Effective: Combine(c.master, own, now), Cost: c.cost[s.Name], Limit: c.limit(c.fuses[s.Name]), Reads: c.reads[s.Name], Rows: s.Rows})
	}
	c.mu.Unlock()
	out.Protect = c.Protection()
	return out
}
