package metrics

import (
	"math"
	"time"
)

const (
	Tier0Step = time.Second
	Tier0Len  = 7200
	Tier1Step = 10 * time.Second
	Tier1Len  = 8640
	Tier2Step = time.Minute
	Tier2Len  = 10080
	Tiers     = 3
)

type Tier struct {
	Step time.Duration
	Len  int
	Agg  bool
}

var TierSpec = [Tiers]Tier{
	{Step: Tier0Step, Len: Tier0Len},
	{Step: Tier1Step, Len: Tier1Len, Agg: true},
	{Step: Tier2Step, Len: Tier2Len, Agg: true},
}

func (t Tier) Depth() time.Duration { return t.Step * time.Duration(t.Len) }

type Point struct {
	Min, Avg, Max float64
}

var unknown = math.NaN()

type ring struct {
	step  time.Duration
	avg   []float64
	lo    []float64
	hi    []float64
	head  int
	last  int64
	count int
}

func newRing(t Tier) ring {
	r := ring{step: t.Step, avg: make([]float64, t.Len)}
	if t.Agg {
		r.lo, r.hi = make([]float64, t.Len), make([]float64, t.Len)
	}
	for i := range r.avg {
		r.avg[i] = unknown
		if t.Agg {
			r.lo[i], r.hi[i] = unknown, unknown
		}
	}
	return r
}

func (r *ring) stepSec() int64 { return int64(r.step / time.Second) }

func (r *ring) slot(unix int64) int64 { return unix - unix%r.stepSec() }

func (r *ring) set(unix int64, p Point) {
	n := len(r.avg)
	switch {
	case r.last == 0:
		r.head, r.last, r.count = 0, unix, 1
	case unix < r.last:
		return
	case unix > r.last:
		steps := int((unix - r.last) / r.stepSec())
		if steps >= n {

			for i := range r.avg {
				r.clear(i)
			}
			r.head, r.last, r.count = 0, unix, 1
		} else {
			for i := 0; i < steps; i++ {
				r.head = (r.head + 1) % n
				r.clear(r.head)
				if r.count < n {
					r.count++
				}
			}
			r.last = unix
		}
	}
	r.avg[r.head] = p.Avg
	if r.lo != nil {
		r.lo[r.head], r.hi[r.head] = p.Min, p.Max
	}
}

func (r *ring) clear(i int) {
	r.avg[i] = unknown
	if r.lo != nil {
		r.lo[i], r.hi[i] = unknown, unknown
	}
}

func (r *ring) at(unix int64) (Point, bool) {
	if r.last == 0 || unix > r.last {
		return Point{}, false
	}
	back := int((r.last - unix) / r.stepSec())
	if back >= r.count {
		return Point{}, false
	}
	i := ((r.head-back)%len(r.avg) + len(r.avg)) % len(r.avg)
	p := Point{Avg: r.avg[i], Min: r.avg[i], Max: r.avg[i]}
	if r.lo != nil {
		p.Min, p.Max = r.lo[i], r.hi[i]
	}
	return p, true
}

type acc struct {
	bucket int64
	lo, hi float64
	sum    float64
	n      int
}

type Series struct {
	rings [Tiers]ring
	accs  [Tiers]acc
}

func New() *Series {
	s := &Series{}
	for i, t := range TierSpec {
		s.rings[i] = newRing(t)
	}
	return s
}

func (s *Series) Add(t time.Time, v float64) {
	unix := t.Unix()
	s.rings[0].set(s.rings[0].slot(unix), Point{Min: v, Avg: v, Max: v})
	for i := 1; i < Tiers; i++ {
		r, a := &s.rings[i], &s.accs[i]
		b := r.slot(unix)
		if b != a.bucket {
			s.commit(i)
			a.bucket, a.lo, a.hi, a.sum, a.n = b, unknown, unknown, 0, 0
		}
		if math.IsNaN(v) {
			continue
		}
		if a.n == 0 || v < a.lo {
			a.lo = v
		}
		if a.n == 0 || v > a.hi {
			a.hi = v
		}
		a.sum += v
		a.n++
	}
}

func (s *Series) commit(i int) {
	a := &s.accs[i]
	if a.bucket == 0 {
		return
	}
	p := Point{Min: unknown, Avg: unknown, Max: unknown}
	if a.n > 0 {
		p = Point{Min: a.lo, Avg: a.sum / float64(a.n), Max: a.hi}
	}
	s.rings[i].set(a.bucket, p)
}

func (s *Series) Last() time.Time {
	if s.rings[0].last == 0 {
		return time.Time{}
	}
	return time.Unix(s.rings[0].last, 0)
}

func (s *Series) Len() (n int) {
	for i := range s.rings {
		n += len(s.rings[i].avg) + len(s.rings[i].lo) + len(s.rings[i].hi)
	}
	return n
}

func (s *Series) Cap() (n int) {
	for i := range s.rings {
		n += cap(s.rings[i].avg) + cap(s.rings[i].lo) + cap(s.rings[i].hi)
	}
	return n
}
