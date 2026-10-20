package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type unitState struct {
	Active   string
	Sub      string
	Result   string
	Restarts int
	Burst    int
	Window   time.Duration
	Pause    time.Duration
}

func (s unitState) failed() bool { return s.Active == "failed" }

func crashLoop(s unitState, base int) bool {
	if s.failed() {
		return true
	}
	return s.Burst > 0 && s.Restarts-base >= s.Burst
}

type unitOps struct {
	state       func(unit string) (unitState, error)
	wait        func(d time.Duration)
	stop        func(unit string) error
	start       func(unit string) error
	mask        func(unit string) error
	unmask      func(unit string) error
	resetFailed func(unit string) error
}

func systemdOps() *unitOps {
	return &unitOps{
		state:       unitStateOf,
		wait:        time.Sleep,
		stop:        func(u string) error { return systemctl("stop", u) },
		start:       func(u string) error { return systemctl("start", u) },
		mask:        func(u string) error { return systemctl("mask", "--runtime", u) },
		unmask:      func(u string) error { return systemctl("unmask", "--runtime", u) },
		resetFailed: func(u string) error { return systemctl("reset-failed", u) },
	}
}

var unitStateProps = []string{"ActiveState", "SubState", "Result", "NRestarts", "StartLimitBurst", "StartLimitIntervalUSec", "RestartUSec"}

func failedStably(ops *unitOps, unit string) bool {
	st, err := ops.state(unit)
	if err != nil || !st.failed() {
		return false
	}
	d := st.Pause
	if d < time.Second {
		d = time.Second
	}
	ops.wait(d)
	st, err = ops.state(unit)
	return err == nil && st.failed()
}

func unitStateOf(unit string) (unitState, error) {
	bin, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return unitState{}, err
	}
	args := []string{"show", unit}
	for _, p := range unitStateProps {
		args = append(args, "-p", p)
	}
	out, err := exec.Command(bin, args...).Output() //nolint:gosec
	if err != nil {
		return unitState{}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	return parseUnitState(out)
}

func parseUnitState(out []byte) (unitState, error) {
	var s unitState
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			s.Active = v
		case "SubState":
			s.Sub = v
		case "Result":
			s.Result = v
		case "NRestarts":
			s.Restarts, _ = strconv.Atoi(v)
		case "StartLimitBurst":
			s.Burst, _ = strconv.Atoi(v)
		case "StartLimitIntervalUSec":
			s.Window = parseTimeSpan(v)
		case "RestartUSec":
			s.Pause = parseTimeSpan(v)
		}
	}
	if s.Active == "" {
		return s, fmt.Errorf("systemctl show: состояние службы не прочитано")
	}
	return s, nil
}

func parseTimeSpan(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" || v == "infinity" {
		return 0
	}
	units := []struct {
		suffix string
		d      time.Duration
	}{
		{"usec", time.Microsecond}, {"us", time.Microsecond}, {"µs", time.Microsecond},
		{"msec", time.Millisecond}, {"ms", time.Millisecond},
		{"months", 30 * 24 * time.Hour}, {"month", 30 * 24 * time.Hour},
		{"weeks", 7 * 24 * time.Hour}, {"week", 7 * 24 * time.Hour}, {"w", 7 * 24 * time.Hour},
		{"days", 24 * time.Hour}, {"day", 24 * time.Hour}, {"d", 24 * time.Hour},
		{"hours", time.Hour}, {"hour", time.Hour}, {"hr", time.Hour}, {"h", time.Hour},
		{"minutes", time.Minute}, {"minute", time.Minute}, {"min", time.Minute}, {"m", time.Minute},
		{"seconds", time.Second}, {"second", time.Second}, {"sec", time.Second}, {"s", time.Second},
	}
	var total time.Duration
	for _, tok := range strings.Fields(v) {
		matched := false
		for _, u := range units {
			if num, ok := strings.CutSuffix(tok, u.suffix); ok {
				f, err := strconv.ParseFloat(num, 64)
				if err != nil {
					return 0
				}
				total += time.Duration(f * float64(u.d))
				matched = true
				break
			}
		}
		if !matched {

			f, err := strconv.ParseFloat(tok, 64)
			if err != nil {
				return 0
			}
			total += time.Duration(f * float64(time.Second))
		}
	}
	return total
}
