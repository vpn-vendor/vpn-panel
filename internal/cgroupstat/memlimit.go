package cgroupstat

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

const (
	SoftRatio = 0.9

	SoftFloor = 100 << 20
)

func EffectiveMemoryMax() (bytes uint64, ok bool) {
	data, err := os.ReadFile(selfCgroup)
	if err != nil {
		return 0, false
	}
	p, ok := unifiedPath(data)
	if !ok {
		return 0, false
	}
	var limits []string
	for dir := p; ; dir = filepath.Dir(dir) {

		raw, err := os.ReadFile(filepath.Join(cgroupRoot, dir, "memory.max")) //nolint:gosec
		if err == nil {
			limits = append(limits, string(raw))
		}
		if dir == "/" || dir == "." {
			break
		}
	}
	return minLimit(limits)
}

func minLimit(raws []string) (uint64, bool) {
	var best uint64
	found := false
	for _, raw := range raws {
		s := strings.TrimSpace(raw)
		if s == "" || s == "max" {
			continue
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil || v == 0 {
			continue
		}
		if !found || v < best {
			best, found = v, true
		}
	}
	return best, found
}

func ApplySoftLimit() (soft int64, hard uint64, ok bool) {
	hard, ok = EffectiveMemoryMax()
	if !ok {
		return 0, 0, false
	}
	soft = SoftMemoryLimit(hard)
	debug.SetMemoryLimit(soft)
	return soft, hard, true
}

func SoftMemoryLimit(hard uint64) int64 {
	soft := int64(float64(hard) * SoftRatio)
	if soft < SoftFloor {
		soft = SoftFloor
	}
	return soft
}

const MinComfortable = 128 << 20
