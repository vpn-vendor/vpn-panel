package admission

import (
	"container/list"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Signal struct {
	Name string

	Hot func() (bool, string)
}

type Snapshot struct {
	Overloaded  bool
	QueueHot    bool
	SignalHot   bool
	SignalName  string
	SignalWhy   string
	Inflight    int
	Waiting     int
	Loopback    int
	Shed        [3]uint64
	Served      uint64
	EpisodeShed [3]uint64
	Episodes    uint64
	Since       time.Time
}

type EpisodeFunc func(started bool, s Snapshot)

type Gate struct {
	next    http.Handler
	rules   []Rule
	pol     Policy
	trusted func(*http.Request) bool
	signals []Signal
	episode EpisodeFunc
	now     func() time.Time

	mu       sync.Mutex
	net      lane
	loop     lane
	shedNow  int
	winStart time.Time
	winMin   time.Duration
	winCount int
	queueHot bool

	sigChecked time.Time
	sigHot     bool
	sigName    string
	sigWhy     string

	inEpisode   bool
	episodeAt   time.Time
	events      chan episodeEvent
	episodes    uint64
	shed        [3]uint64
	episodeShed [3]uint64
	served      uint64
}

type lane struct {
	cap      int
	reserve  int
	inflight int
	crit     *list.List
	ord      *list.List
}

type episodeEvent struct {
	started bool
	snap    Snapshot
}

const episodeBuffer = 16

type waiter struct {
	ch    chan struct{}
	limit int
}

func New(next http.Handler, rules []Rule, pol Policy, trusted func(*http.Request) bool, signals []Signal, episode EpisodeFunc) *Gate {
	g := &Gate{next: next, rules: rules, pol: pol, trusted: trusted, signals: signals, episode: episode, now: time.Now}
	g.net = lane{cap: pol.Ceiling, reserve: pol.Reserve, crit: list.New(), ord: list.New()}
	g.loop = lane{cap: pol.LoopbackCeiling, crit: list.New(), ord: list.New()}
	if episode != nil {

		g.events = make(chan episodeEvent, episodeBuffer)
		go func() {
			for ev := range g.events {
				episode(ev.started, ev.snap)
			}
		}()
	}
	return g
}

func (g *Gate) emitLocked(started bool) {
	if g.events == nil {
		return
	}
	select {
	case g.events <- episodeEvent{started: started, snap: g.snapshotLocked()}:
	default:
	}
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	class, _ := Classify(g.rules, r.Method, r.URL.Path)
	if isLoopback(r.RemoteAddr) {
		if !g.acquire(&g.loop, class, nil, g.waitFor(class)) {
			g.refuse(w, class)
			return
		}
		defer g.release(&g.loop, class)
		g.next.ServeHTTP(w, r)
		return
	}
	var trusted func() bool
	if g.trusted != nil && class == Critical {
		trusted = func() bool { return g.trusted(r) }
	}
	if !g.acquire(&g.net, class, trusted, g.waitFor(class)) {
		g.refuse(w, class)
		return
	}
	defer g.release(&g.net, class)
	g.next.ServeHTTP(w, r)
}

func (g *Gate) waitFor(class Class) time.Duration {
	switch class {
	case Critical:
		return g.pol.CriticalWait
	case Ordinary:
		return g.pol.OrdinaryWait
	}
	return 0
}

func (g *Gate) acquire(l *lane, class Class, trusted func() bool, wait time.Duration) bool {
	now := g.now()
	g.mu.Lock()
	g.pollSignalsLocked(now)
	overloaded := g.overloadedLocked(now)
	limit := l.cap - l.reserve
	if class == Sheddable {
		if l == &g.net && (overloaded || g.shedNow >= g.pol.ShedCeiling) || l.inflight >= limit {
			g.shedLocked(class)
			g.mu.Unlock()
			return false
		}
		l.inflight++
		if l == &g.net {
			g.shedNow++
		}
		g.recordWaitLocked(now, 0)
		g.mu.Unlock()
		return true
	}
	if class == Critical && l.reserve > 0 && l.inflight >= limit && trusted != nil {
		g.mu.Unlock()
		ok := trusted()
		g.mu.Lock()
		if ok {
			limit = l.cap
		}
	}
	if l.inflight < limit {
		l.inflight++
		g.recordWaitLocked(now, 0)
		g.mu.Unlock()
		return true
	}
	if l.crit.Len()+l.ord.Len() >= g.pol.QueueCeiling || wait <= 0 {
		g.shedLocked(class)
		g.mu.Unlock()
		return false
	}
	wt := &waiter{ch: make(chan struct{}, 1), limit: limit}
	var el *list.Element
	if class == Critical {
		el = l.crit.PushBack(wt)
	} else {
		el = l.ord.PushBack(wt)
	}
	g.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-wt.ch:
		g.mu.Lock()
		g.recordWaitLocked(g.now(), g.now().Sub(now))
		g.mu.Unlock()
		return true
	case <-timer.C:
		g.mu.Lock()
		defer g.mu.Unlock()
		select {
		case <-wt.ch:
			g.recordWaitLocked(g.now(), g.now().Sub(now))
			return true
		default:
		}
		if class == Critical {
			l.crit.Remove(el)
		} else {
			l.ord.Remove(el)
		}
		g.recordWaitLocked(g.now(), g.now().Sub(now))
		g.shedLocked(class)
		return false
	}
}

func (g *Gate) release(l *lane, class Class) {
	g.mu.Lock()
	defer g.mu.Unlock()
	l.inflight--
	g.served++
	if l == &g.net && class == Sheddable {
		g.shedNow--
	}

	for _, q := range []*list.List{l.crit, l.ord} {
		if q.Len() == 0 {
			continue
		}
		wt := q.Front().Value.(*waiter)
		if l.inflight < wt.limit {
			q.Remove(q.Front())
			l.inflight++
			wt.ch <- struct{}{}
			return
		}
	}
}

func (g *Gate) recordWaitLocked(now time.Time, wait time.Duration) {
	if g.winStart.IsZero() || now.Sub(g.winStart) >= g.pol.WaitInterval {
		if !g.winStart.IsZero() {
			g.queueHot = g.winCount > 0 && g.winMin > g.pol.WaitTarget
		}
		g.winStart, g.winMin, g.winCount = now, wait, 1
		g.checkEpisodeLocked(now)
		return
	}
	g.winCount++
	if wait < g.winMin {
		g.winMin = wait
	}
}

func (g *Gate) pollSignalsLocked(now time.Time) {
	if len(g.signals) == 0 || (!g.sigChecked.IsZero() && now.Sub(g.sigChecked) < g.pol.SignalEvery) {
		return
	}
	g.sigChecked = now
	g.sigHot, g.sigName, g.sigWhy = false, "", ""
	for _, s := range g.signals {
		if hot, why := s.Hot(); hot {
			g.sigHot, g.sigName, g.sigWhy = true, s.Name, why
			break
		}
	}
	g.checkEpisodeLocked(now)
}

func (g *Gate) overloadedLocked(now time.Time) bool {

	if g.queueHot && !g.winStart.IsZero() && now.Sub(g.winStart) >= 2*g.pol.WaitInterval {
		g.queueHot = false
		g.checkEpisodeLocked(now)
	}
	return g.queueHot || g.sigHot
}

func (g *Gate) checkEpisodeLocked(now time.Time) {
	over := g.queueHot || g.sigHot
	switch {
	case over && !g.inEpisode:
		g.inEpisode, g.episodeAt = true, now
		g.episodes++
		g.episodeShed = [3]uint64{}
		g.emitLocked(true)
	case !over && g.inEpisode:
		g.inEpisode = false
		g.emitLocked(false)
		g.episodeAt = time.Time{}
	}
}

func (g *Gate) shedLocked(class Class) {
	g.shed[class]++
	g.episodeShed[class]++
}

func (g *Gate) refuse(w http.ResponseWriter, class Class) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", strconv.Itoa(int(g.pol.RetryAfter/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	msg := "Панель занята: слишком много запросов из сети. Повторите через несколько секунд.\n"
	if class == Critical {
		msg = "Панель перегружена и не смогла выполнить действие. Повторите; если повторяется — войдите с рабочего стола сервера или через консольную команду.\n"
	}
	_, _ = w.Write([]byte(msg))
}

func (g *Gate) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pollSignalsLocked(g.now())
	g.overloadedLocked(g.now())
	return g.snapshotLocked()
}

func (g *Gate) snapshotLocked() Snapshot {
	return Snapshot{
		Overloaded: g.queueHot || g.sigHot, QueueHot: g.queueHot,
		SignalHot: g.sigHot, SignalName: g.sigName, SignalWhy: g.sigWhy,
		Inflight: g.net.inflight, Waiting: g.net.crit.Len() + g.net.ord.Len(), Loopback: g.loop.inflight,
		Shed: g.shed, Served: g.served, EpisodeShed: g.episodeShed, Episodes: g.episodes, Since: g.episodeAt,
	}
}

func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
