package securitylog

import "time"

type Key struct {
	Event string
	IP    string
}

const overflowIP = "*"

type Pending struct {
	ID    uint
	Extra int
	Last  time.Time
}

type entry struct {
	id    uint
	start time.Time
	last  time.Time
	extra int
}

type Deduper struct {
	window time.Duration
	max    int
	m      map[Key]*entry
}

func NewDeduper(window time.Duration, maxKeys int) *Deduper {
	return &Deduper{window: window, max: maxKeys, m: map[Key]*entry{}}
}

func (d *Deduper) Resolve(k Key) Key {
	if _, ok := d.m[k]; ok || d.tracked() < d.max {
		return k
	}
	return Key{Event: k.Event, IP: overflowIP}
}

func (d *Deduper) Coalesce(k Key, now time.Time) bool {
	e, ok := d.m[k]
	if !ok || now.Sub(e.start) >= d.window {
		return false
	}
	e.extra++
	e.last = now
	return true
}

func (d *Deduper) Open(k Key, id uint, now time.Time) {
	d.m[k] = &entry{id: id, start: now, last: now}
}

func (d *Deduper) Expire(now time.Time) []Pending {
	var out []Pending
	for k, e := range d.m {
		if now.Sub(e.start) < d.window {
			continue
		}
		if e.extra > 0 {
			out = append(out, Pending{ID: e.id, Extra: e.extra, Last: e.last})
		}
		delete(d.m, k)
	}
	return out
}

func (d *Deduper) All() []Pending {
	var out []Pending
	for k, e := range d.m {
		if e.extra > 0 {
			out = append(out, Pending{ID: e.id, Extra: e.extra, Last: e.last})
		}
		delete(d.m, k)
	}
	return out
}

func (d *Deduper) tracked() int {
	n := 0
	for k := range d.m {
		if k.IP != overflowIP {
			n++
		}
	}
	return n
}

func (d *Deduper) Len() int { return len(d.m) }
