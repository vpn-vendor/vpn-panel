package reliability

import (
	"sort"
	"time"
)

type Event struct {
	Code    string
	At      time.Time
	Last    time.Time
	Repeats int
}

func (e Event) end() time.Time {
	if e.Last.After(e.At) {
		return e.Last
	}
	return e.At
}

func Count(events []Event, codes map[string]bool, from, to time.Time) int {
	n := 0
	for _, e := range events {
		if codes[e.Code] && !e.At.Before(from) && !e.At.After(to) {
			n += 1 + e.Repeats
		}
	}
	return n
}

type Stretch struct {
	Up, Down string
	Events   []Event
	Breaks   []time.Time
	From     time.Time
	Now      time.Time

	LiveUp bool
}

func Longest(s Stretch) (time.Duration, bool) {
	type item struct {
		at, end time.Time
		kind    int
	}
	var items []item
	for _, e := range s.Events {
		switch e.Code {
		case s.Up:
			items = append(items, item{e.At, e.end(), 0})
		case s.Down:
			items = append(items, item{e.At, e.end(), 1})
		}
	}
	for _, b := range s.Breaks {
		items = append(items, item{b, b, 2})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })

	var (
		best      time.Duration
		seen      bool
		upSince   time.Time
		lastBreak time.Time
		lastEvent time.Time
	)
	finish := func(end time.Time) {
		start := upSince
		if start.Before(s.From) {
			start = s.From
		}
		if end.After(s.Now) {
			end = s.Now
		}
		if d := end.Sub(start); end.After(s.From) && d >= 0 {
			seen = true
			if d > best {
				best = d
			}
		}
		upSince = time.Time{}
	}
	for _, it := range items {
		if it.kind != 2 && it.end.After(lastEvent) {
			lastEvent = it.end
		}
		switch it.kind {
		case 0:

			if upSince.IsZero() || it.end.After(upSince) {
				upSince = it.end
			}
		case 1:
			if upSince.IsZero() {
				continue
			}
			switch {
			case it.at.After(upSince):
				finish(it.at)
			case !it.end.Before(upSince):

				upSince = time.Time{}
			}
		case 2:
			lastBreak = it.at
			if !upSince.IsZero() && it.at.After(upSince) {
				finish(it.at)
			}
			upSince = time.Time{}
		}
	}
	if s.LiveUp {
		switch {
		case !upSince.IsZero():
			finish(s.Now)
		case !lastBreak.IsZero() && lastBreak.After(lastEvent):

			upSince = lastBreak
			finish(s.Now)
		}
	}
	return best, seen
}
