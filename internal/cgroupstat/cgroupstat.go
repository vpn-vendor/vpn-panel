package cgroupstat

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	selfCgroup = "/proc/self/cgroup"
	cgroupRoot = "/sys/fs/cgroup"
)

func Throttled() (usec uint64, ok bool) {
	data, err := os.ReadFile(selfCgroup)
	if err != nil {
		return 0, false
	}
	p, ok := unifiedPath(data)
	if !ok {
		return 0, false
	}

	stat, err := os.ReadFile(filepath.Join(cgroupRoot, p, "cpu.stat")) //nolint:gosec
	if err != nil {
		return 0, false
	}
	return throttledUsec(stat)
}

func unifiedPath(data []byte) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		p := strings.TrimPrefix(line, "0::")

		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return "", false
		}
		return filepath.Clean(p), true
	}
	return "", false
}

func throttledUsec(stat []byte) (uint64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(stat))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || fields[0] != "throttled_usec" {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}
