package metrics

import (
	"math"
	"time"
)

const MaxPoints = 4000

var Ladder = []time.Duration{
	time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 30 * time.Second,
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

type Plan struct {
	Tier  int
	Step  time.Duration
	Width int
}

func PlanFor(now, from, to time.Time, width int) Plan {
	if width <= 0 || width > MaxPoints {
		width = MaxPoints
	}
	span := to.Sub(from)
	if span <= 0 {
		span = time.Second
	}
	want := span / time.Duration(width)
	step := Ladder[len(Ladder)-1]
	for _, l := range Ladder {
		if l >= want {
			step = l
			break
		}
	}
	tier := Tiers - 1
	for i := Tiers - 1; i >= 0; i-- {
		t := TierSpec[i]
		if t.Step <= step && !from.Before(now.Add(-t.Depth())) {
			tier = i
		}
	}
	if s := TierSpec[tier].Step; step < s {
		step = s
	}
	return Plan{Tier: tier, Step: step, Width: width}
}

func (s *Series) Range(p Plan, from, to time.Time) []Point {
	r := &s.rings[p.Tier]
	stepSec := int64(p.Step / time.Second)
	start := from.Unix() - from.Unix()%stepSec
	n := int((to.Unix()-start)/stepSec) + 1
	width := p.Width
	if width <= 0 || width > MaxPoints {
		width = MaxPoints
	}

	if n > width {
		start += int64(n-width) * stepSec
		n = width
	}
	if n <= 0 {
		return nil
	}
	out := make([]Point, n)
	for i := range out {
		lo, hi, sum, cnt := unknown, unknown, 0.0, 0
		b0 := start + int64(i)*stepSec
		for u := b0; u < b0+stepSec; u += r.stepSec() {
			pt, ok := r.at(r.slot(u))
			if !ok || math.IsNaN(pt.Avg) {
				continue
			}
			if cnt == 0 || pt.Min < lo {
				lo = pt.Min
			}
			if cnt == 0 || pt.Max > hi {
				hi = pt.Max
			}
			sum += pt.Avg
			cnt++
		}
		if cnt == 0 {
			out[i] = Point{Min: unknown, Avg: unknown, Max: unknown}
		} else {
			out[i] = Point{Min: lo, Avg: sum / float64(cnt), Max: hi}
		}
	}
	return out
}
