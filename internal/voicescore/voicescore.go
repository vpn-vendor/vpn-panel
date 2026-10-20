package voicescore

import "math"

const (
	GoodR = 70.0
	PoorR = 60.0
)

type Level int

const (
	Good Level = iota
	Fair
	Poor
)

func R(rttMs, jitterMs, lossPct float64) float64 {
	eff := rttMs + 2*jitterMs + 10
	r := 93.2 - eff/40
	if eff >= 160 {
		r = 93.2 - (eff-120)/10
	}
	r -= 2.5 * lossPct
	return math.Max(0, math.Min(100, r))
}

func MOS(r float64) float64 {
	if r <= 0 {
		return 1
	}
	m := 1 + 0.035*r + 7e-6*r*(r-60)*(100-r)
	return math.Max(1, math.Min(4.5, m))
}

func Score(rttMs, jitterMs, lossPct float64) (float64, Level) {
	r := R(rttMs, jitterMs, lossPct)
	switch {
	case r >= GoodR:
		return MOS(r), Good
	case r >= PoorR:
		return MOS(r), Fair
	default:
		return MOS(r), Poor
	}
}

func Threshold(r float64) float64 { return MOS(r) }
