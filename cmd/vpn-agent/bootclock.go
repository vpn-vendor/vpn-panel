package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	procUptime = "/proc/uptime"
	procBootID = "/proc/sys/kernel/random/boot_id"
)

type bootInstant time.Duration

func (b bootInstant) IsZero() bool                    { return b == 0 }
func (b bootInstant) Before(o bootInstant) bool       { return b < o }
func (b bootInstant) Add(d time.Duration) bootInstant { return b + bootInstant(d) }
func (b bootInstant) Sub(o bootInstant) time.Duration { return time.Duration(b - o) }

func parseUptime(s string) (time.Duration, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	secs, err := strconv.ParseFloat(f[0], 64)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs * float64(time.Second)), true
}

func bootNow() (bootInstant, bool) {
	data, err := os.ReadFile(procUptime)
	if err != nil {
		return 0, false
	}
	d, ok := parseUptime(string(data))
	return bootInstant(d), ok
}

func bootID() string {
	data, err := os.ReadFile(procBootID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func bootStamp() (bootInstant, string) {
	now, ok := bootNow()
	if !ok {
		return 0, ""
	}
	return now, bootID()
}

func bootDeadline(d time.Duration) bootInstant {
	now, ok := bootNow()
	if !ok {
		return 0
	}
	return now.Add(d)
}

func due(at bootInstant) bool {
	if at.IsZero() {
		return true
	}
	now, ok := bootNow()
	if !ok {
		return true
	}
	return !now.Before(at)
}

func sinceBoot(at bootInstant, stampID string) int64 {
	if at.IsZero() {
		return -1
	}
	now, ok := bootNow()
	if !ok {
		return -1
	}
	if stampID != "" && stampID != bootID() {
		return -1
	}
	return int64(now.Sub(at).Seconds())
}
