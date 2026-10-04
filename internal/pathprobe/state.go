package pathprobe

import (
	"math/rand/v2"
	"time"
)

const (
	Interval      = time.Second
	JitterShare   = 0.3
	Timeout       = 2 * time.Second
	DownAfter     = 5
	UpAfter       = 5
	VerdictProbes = 1000
)

func NextInterval() time.Duration {
	spread := float64(Interval) * JitterShare
	return Interval + time.Duration((rand.Float64()*2-1)*spread) //nolint:gosec
}

type State int

const (
	Unknown State = iota
	NoAnswer
	Up
	Down
)

func (s State) String() string {
	switch s {
	case NoAnswer:
		return "цель не отвечает на пробы"
	case Up:
		return "путь доступен"
	case Down:
		return "путь недоступен"
	}
	return "не измеряется"
}

type Hysteresis struct {
	state  State
	fails  int
	oks    int
	everUp bool
}

func (h *Hysteresis) Feed(ok bool) (State, bool) {
	prev := h.state
	if ok {
		h.oks++
		h.fails = 0
		if h.state != Up && h.oks >= UpAfter {
			h.state, h.everUp = Up, true
		}
		if h.state == Unknown || h.state == NoAnswer {

			h.state, h.everUp = Up, true
		}
	} else {
		h.fails++
		h.oks = 0
		if h.fails >= DownAfter {
			if h.everUp {
				h.state = Down
			} else {
				h.state = NoAnswer
			}
		}
	}
	return h.state, h.state != prev
}

func (h *Hysteresis) State() State { return h.state }

type Window struct {
	ring  [VerdictProbes]bool
	head  int
	count int
	fails int
}

func (w *Window) Add(ok bool) {
	if w.count == VerdictProbes && !w.ring[w.head] {
		w.fails--
	}
	w.ring[w.head] = ok
	if !ok {
		w.fails++
	}
	w.head = (w.head + 1) % VerdictProbes
	if w.count < VerdictProbes {
		w.count++
	}
}

func (w *Window) Loss() (percent float64, enough bool) {
	if w.count == 0 {
		return 0, false
	}
	return 100 * float64(w.fails) / float64(w.count), w.count >= VerdictProbes
}

func Quorum(results []bool, k int) bool {
	n := 0
	for _, ok := range results {
		if ok {
			n++
		}
	}
	return k > 0 && n >= k
}
