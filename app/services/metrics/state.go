package metrics

import (
	"strconv"
	"strings"
	"time"
)

type Mode int

const (
	On Mode = iota
	Paused
	Memory
	Off
)

func (m Mode) String() string {
	switch m {
	case On:
		return "включён"
	case Paused:
		return "пауза"
	case Memory:
		return "только в памяти"
	case Off:
		return "выключен"
	}
	return "?"
}

type State struct {
	Mode  Mode
	Until time.Time
}

func Parse(s string) State {
	switch {
	case s == "off":
		return State{Mode: Off}
	case s == "memory":
		return State{Mode: Memory}
	case strings.HasPrefix(s, "pause:"):
		u, err := strconv.ParseInt(strings.TrimPrefix(s, "pause:"), 10, 64)
		if err != nil || u <= 0 {
			return State{Mode: On}
		}
		return State{Mode: Paused, Until: time.Unix(u, 0)}
	}
	return State{Mode: On}
}

func (s State) String() string {
	switch s.Mode {
	case Off:
		return "off"
	case Memory:
		return "memory"
	case Paused:
		return "pause:" + strconv.FormatInt(s.Until.Unix(), 10)
	}
	return "on"
}

func (s State) Now(now time.Time) State {
	if s.Mode == Paused && !now.Before(s.Until) {
		return State{Mode: On}
	}
	return s
}

func Combine(master, src State, now time.Time) State {
	m, s := master.Now(now), src.Now(now)
	if m.Mode == Off || s.Mode == Off {
		return State{Mode: Off}
	}
	if m.Mode == Paused || s.Mode == Paused {
		until := m.Until
		if s.Until.After(until) {
			until = s.Until
		}
		return State{Mode: Paused, Until: until}
	}
	if m.Mode == Memory || s.Mode == Memory {
		return State{Mode: Memory}
	}
	return State{Mode: On}
}

func (s State) Collects() bool { return s.Mode == On || s.Mode == Memory }

func (s State) Persists() bool { return s.Mode == On }
