package reliability

import (
	"log"
	"sort"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

type Span int

const (
	SpanUnknown Span = iota
	SpanUp
	SpanDown
	SpanOff
)

type Life struct {
	Booted, Started, Seen time.Time
}

type UptimeInput struct {
	Up, Down, NoAnswer string
	Events             []Event
	Breaks             []time.Time
	Lives              []Life
	From, Now          time.Time
	Cells              int
}

type Uptime struct {
	Up, Down, Off time.Duration
	Outages, Offs int
	Cells         []Span
}

func (u Uptime) Percent() (float64, bool) {
	seen := u.Up + u.Down
	if seen <= 0 {
		return 0, false
	}
	return 100 * float64(u.Up) / float64(seen), true
}

type change struct {
	at    time.Time
	state Span
	order int
}

func (u Uptime) Known() time.Duration { return u.Up + u.Down + u.Off }

func ComputeUptime(in UptimeInput) Uptime {
	var changes []change
	for _, e := range in.Events {
		switch e.Code {
		case in.Up:

			changes = append(changes, change{e.end(), SpanUp, 1})
		case in.Down:
			changes = append(changes, change{e.At, SpanDown, 1})
		case in.NoAnswer:
			changes = append(changes, change{e.At, SpanUnknown, 1})
		}
	}
	for _, b := range in.Breaks {
		changes = append(changes, change{b, SpanUnknown, 0})
	}
	var offs [][2]time.Time
	for i, l := range in.Lives {

		changes = append(changes, change{l.Booted, SpanUnknown, 0}, change{l.Started, SpanUnknown, 0})
		if i > 0 {
			if prev := in.Lives[i-1].Seen; l.Booted.After(prev) {
				offs = append(offs, [2]time.Time{prev, l.Booted})
			}
		}
	}
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].at.Equal(changes[j].at) {
			return changes[i].order < changes[j].order
		}
		return changes[i].at.Before(changes[j].at)
	})

	var out Uptime
	if !in.Now.After(in.From) {
		return out
	}
	cells := max(in.Cells, 0)
	out.Cells = make([]Span, cells)
	cellLen := in.Now.Sub(in.From) / time.Duration(max(cells, 1))
	cellAt := func(i int) time.Time { return in.From.Add(cellLen * time.Duration(i)) }

	bounds := []time.Time{in.From, in.Now}
	for _, c := range changes {
		bounds = append(bounds, c.at)
	}
	for _, o := range offs {
		bounds = append(bounds, o[0], o[1])
	}
	for i := 1; i < cells; i++ {
		bounds = append(bounds, cellAt(i))
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].Before(bounds[j]) })

	type tally [4]time.Duration
	per := make([]tally, cells)
	state, next, prevState := SpanUnknown, 0, Span(-1)
	isOff := func(t time.Time) bool {
		for _, o := range offs {
			if !t.Before(o[0]) && t.Before(o[1]) {
				return true
			}
		}
		return false
	}
	for i := 0; i+1 < len(bounds); i++ {
		a, b := bounds[i], bounds[i+1]
		for next < len(changes) && !changes[next].at.After(a) {
			state = changes[next].state
			next++
		}

		if !b.After(a) || !b.After(in.From) || !a.Before(in.Now) {
			continue
		}
		if a.Before(in.From) {
			a = in.From
		}
		if b.After(in.Now) {
			b = in.Now
		}
		s := state
		if isOff(a) {
			s = SpanOff
		}
		d := b.Sub(a)
		switch s {
		case SpanUp:
			out.Up += d
		case SpanDown:
			out.Down += d
			if prevState != SpanDown {
				out.Outages++
			}
		case SpanOff:
			out.Off += d
			if prevState != SpanOff {
				out.Offs++
			}
		}
		prevState = s
		if cells > 0 {
			ci := min(int(a.Sub(in.From)/cellLen), cells-1)
			per[ci][s] += d
		}
	}
	for i, t := range per {

		switch {
		case t[SpanDown] > 0:
			out.Cells[i] = SpanDown
		case t[SpanOff] > 0:
			out.Cells[i] = SpanOff
		case t[SpanUp] > 0:
			out.Cells[i] = SpanUp
		}
	}
	return out
}

const Month = 30 * Day

type uptimeKey struct {
	kind   pathmon.Kind
	window time.Duration
	cells  int
}

var (
	uptimeMu    sync.Mutex
	uptimeCache = map[uptimeKey]uptimeEntry{}
)

type uptimeEntry struct {
	u  Uptime
	at time.Time
}

func ReadUptime(kind pathmon.Kind, window time.Duration, cells int) Uptime {
	now := time.Now()
	key := uptimeKey{kind, window, cells}
	uptimeMu.Lock()
	defer uptimeMu.Unlock()
	if e, ok := uptimeCache[key]; ok && now.Sub(e.at) < CacheFor {
		return e.u
	}
	u, err := loadUptime(now, key)
	if err != nil {
		log.Printf("доступность канала: %v", err)
		return Uptime{}
	}
	uptimeCache[key] = uptimeEntry{u, now}
	return u
}

func loadUptime(now time.Time, key uptimeKey) (Uptime, error) {
	from := now.Add(-key.window)
	in := UptimeInput{
		Up:       pathmon.EventCode(key.kind, pathprobe.Up),
		Down:     pathmon.EventCode(key.kind, pathprobe.Down),
		NoAnswer: pathmon.EventCode(key.kind, pathprobe.NoAnswer),
		From:     from, Now: now, Cells: key.cells,
	}
	var boots []models.Boot
	if err := facades.Orm().Query().OrderBy("id").Find(&boots); err != nil {
		return Uptime{}, err
	}
	for i, b := range boots {
		seen := b.SeenAt
		if i == len(boots)-1 {
			seen = now
		}
		in.Lives = append(in.Lives, Life{Booted: b.BootedAt, Started: b.FirstStartAt, Seen: seen})
		in.Breaks = append(in.Breaks, b.LastStartAt)
	}
	path := []any{in.Up, in.Down, in.NoAnswer}

	anchor := from
	var before models.AuthEvent
	if err := facades.Orm().Query().WhereIn("event", path).Where("occurred_at < ?", from).
		OrderBy("occurred_at", "desc").First(&before); err == nil && before.ID != 0 {
		anchor = before.OccurredAt
	}
	want := append([]any{}, path...)
	breaks := map[string]bool{}
	for _, c := range securitylog.BreakCodes() {
		want = append(want, c)
		breaks[c] = true
	}
	var rows []models.AuthEvent
	if err := facades.Orm().Query().WhereIn("event", want).Where("occurred_at >= ?", anchor).
		OrderBy("occurred_at").Find(&rows); err != nil {
		return Uptime{}, err
	}
	for _, e := range toEvents(rows) {
		if breaks[e.Code] {
			in.Breaks = append(in.Breaks, e.At, e.end())
			continue
		}
		in.Events = append(in.Events, e)
	}
	return ComputeUptime(in), nil
}
