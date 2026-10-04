package reliability

import (
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

const (
	Day  = 24 * time.Hour
	Week = 7 * Day
)

const CacheFor = securitylog.DedupWindow

type Snapshot struct {
	Now time.Time

	Observed time.Time

	DropsDay, DropsWeek int

	Longest   time.Duration
	LongestOK bool

	RebootsWeek int

	UncleanWeek int
	FailuresDay int
}

var (
	cacheMu  sync.Mutex
	cached   Snapshot
	cachedAt time.Time
	cachedUp bool
)

func Read(liveUp bool) Snapshot {
	now := time.Now()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if !cachedAt.IsZero() && now.Sub(cachedAt) < CacheFor && cachedUp == liveUp {
		return cached
	}
	s, err := load(now, liveUp)
	if err != nil {
		log.Printf("счётчики надёжности: %v", err)
		return Snapshot{Now: now}
	}
	cached, cachedAt, cachedUp = s, now, liveUp
	return s
}

type Codes struct {
	Up, Down string
	Failures map[string]bool
	Breaks   map[string]bool
	Unclean  string
}

func CurrentCodes() Codes {
	set := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, c := range list {
			m[c] = true
		}
		return m
	}
	return Codes{
		Up:       pathmon.EventCode(pathmon.Tunnel, pathprobe.Up),
		Down:     pathmon.EventCode(pathmon.Tunnel, pathprobe.Down),
		Failures: set(securitylog.FailureCodes()),
		Breaks:   set(securitylog.BreakCodes()),
		Unclean:  CodeUncleanShutdown,
	}
}

func load(now time.Time, liveUp bool) (Snapshot, error) {
	from := now.Add(-Week)
	codes := CurrentCodes()

	var boots []models.Boot
	if err := facades.Orm().Query().OrderBy("id").Find(&boots); err != nil {
		return Snapshot{}, err
	}

	anchor := from
	var before models.AuthEvent
	if err := facades.Orm().Query().WhereIn("event", []any{codes.Up, codes.Down}).
		Where("occurred_at < ?", from).OrderBy("occurred_at", "desc").First(&before); err == nil && before.ID != 0 {
		anchor = before.OccurredAt
	}
	want := []any{codes.Up, codes.Down}
	for c := range codes.Failures {
		want = append(want, c)
	}
	for c := range codes.Breaks {
		want = append(want, c)
	}
	var rows []models.AuthEvent
	if err := facades.Orm().Query().WhereIn("event", want).Where("occurred_at >= ?", anchor).
		OrderBy("occurred_at").Find(&rows); err != nil {
		return Snapshot{}, err
	}
	return compute(now, liveUp, codes, boots, toEvents(rows)), nil
}

func toEvents(rows []models.AuthEvent) []Event {
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		e := Event{Code: r.Event, At: r.OccurredAt, Repeats: r.RepeatCount}
		if r.LastAt != nil {
			e.Last = *r.LastAt
		}
		out = append(out, e)
	}
	return out
}

func compute(now time.Time, liveUp bool, codes Codes, boots []models.Boot, events []Event) Snapshot {
	from := now.Add(-Week)
	s := Snapshot{Now: now}
	if len(boots) == 0 {
		return s
	}
	s.Observed = boots[0].FirstStartAt
	if s.Observed.Before(from) {
		s.Observed = from
	}

	down := map[string]bool{codes.Down: true}
	s.DropsDay = Count(events, down, now.Add(-Day), now)
	s.DropsWeek = Count(events, down, from, now)
	s.FailuresDay = Count(events, codes.Failures, now.Add(-Day), now)
	s.UncleanWeek = Count(events, map[string]bool{codes.Unclean: true}, from, now)

	for i, b := range boots {
		if i > 0 && !b.BootedAt.Before(from) {
			s.RebootsWeek++
		}
	}

	var breaks []time.Time
	for _, e := range events {
		if codes.Breaks[e.Code] {
			breaks = append(breaks, e.At, e.end())
		}
	}
	current := boots[len(boots)-1]
	for _, b := range boots {

		breaks = append(breaks, b.FirstStartAt, b.LastStartAt)
		if b.ID != current.ID {
			breaks = append(breaks, b.SeenAt)
		}
	}
	s.Longest, s.LongestOK = Longest(Stretch{Up: codes.Up, Down: codes.Down, Events: events,
		Breaks: breaks, From: from, Now: now, LiveUp: liveUp})
	return s
}
