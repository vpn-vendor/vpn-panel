package procstat

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
)

type CPUTimes struct {
	Busy, Total uint64
}

func ParseCPU(stat []byte) (CPUTimes, error) {
	sc := bufio.NewScanner(bytes.NewReader(stat))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var t CPUTimes
		for i, s := range f[1:] {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return CPUTimes{}, err
			}
			t.Total += v
			if i == 3 || i == 4 {
				continue
			}
			t.Busy += v
		}
		return t, nil
	}
	return CPUTimes{}, errors.New("в /proc/stat нет строки cpu")
}

func BusyPercent(prev, cur CPUTimes) (float64, bool) {
	if cur.Total <= prev.Total || cur.Busy < prev.Busy {
		return 0, false
	}
	return 100 * float64(cur.Busy-prev.Busy) / float64(cur.Total-prev.Total), true
}

func ParseLoad1(raw []byte) (float64, error) {
	f := strings.Fields(string(raw))
	if len(f) < 1 {
		return 0, errors.New("пустой /proc/loadavg")
	}
	return strconv.ParseFloat(f[0], 64)
}

type MemInfo struct {
	Total, Avail, Cache, SwapTotal, SwapFree uint64
}

func ParseMemInfo(raw []byte) (MemInfo, error) {
	var m MemInfo
	var buffers, cached, reclaim, shmem uint64
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.Total = v
		case "MemAvailable:":
			m.Avail = v
		case "Buffers:":
			buffers = v
		case "Cached:":
			cached = v
		case "SReclaimable:":
			reclaim = v
		case "Shmem:":
			shmem = v
		case "SwapTotal:":
			m.SwapTotal = v
		case "SwapFree:":
			m.SwapFree = v
		}
	}
	if m.Total == 0 || m.Avail > m.Total {
		return MemInfo{}, errors.New("в /proc/meminfo нет MemTotal или MemAvailable")
	}
	if c := buffers + cached + reclaim; c > shmem {
		m.Cache = c - shmem
	}

	m.Cache = min(m.Cache, m.Avail)
	if m.SwapFree > m.SwapTotal {
		m.SwapFree = m.SwapTotal
	}
	return m, nil
}

func (m MemInfo) UsedPercent() float64 { return 100 * float64(m.Total-m.Avail) / float64(m.Total) }

func (m MemInfo) CachePercent() float64 { return 100 * float64(m.Cache) / float64(m.Total) }

func (m MemInfo) SwapPercent() (float64, bool) {
	if m.SwapTotal == 0 {
		return 0, false
	}
	return 100 * float64(m.SwapTotal-m.SwapFree) / float64(m.SwapTotal), true
}

func ParseMemUsedPercent(raw []byte) (float64, error) {
	m, err := ParseMemInfo(raw)
	if err != nil {
		return 0, err
	}
	return m.UsedPercent(), nil
}

func ParseDiskTicks(raw []byte, names []string) map[string]uint64 {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 13 || !want[f[2]] {
			continue
		}
		if v, err := strconv.ParseUint(f[12], 10, 64); err == nil {
			out[f[2]] = v
		}
	}
	return out
}

func DiskBusyPercent(prev, cur map[string]uint64, elapsedMs float64) (float64, bool) {
	if elapsedMs <= 0 {
		return 0, false
	}
	best, ok := 0.0, false
	for name, c := range cur {
		p, seen := prev[name]
		if !seen || c < p {
			continue
		}
		ok = true
		best = max(best, min(100, 100*float64(c-p)/elapsedMs))
	}
	return best, ok
}

func ParsePressureSome(raw []byte) (float64, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			if strings.HasPrefix(kv, "avg10=") {
				v, err := strconv.ParseFloat(strings.TrimPrefix(kv, "avg10="), 64)
				if err != nil || v < 0 || v > 100 {
					return 0, errors.New("avg10 вне диапазона")
				}
				return v, nil
			}
		}
	}
	return 0, errors.New("в файле давления нет строки some")
}

func ParseLinkSpeed(raw []byte) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func ReadCPU() (CPUTimes, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUTimes{}, err
	}
	return ParseCPU(raw)
}

func ReadLoad1() (float64, error) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	return ParseLoad1(raw)
}

func ReadMemUsedPercent() (float64, error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	return ParseMemUsedPercent(raw)
}

func ReadMemInfo() (MemInfo, error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return MemInfo{}, err
	}
	return ParseMemInfo(raw)
}

func ReadDiskTicks(names []string) (map[string]uint64, error) {
	raw, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	return ParseDiskTicks(raw, names), nil
}

func ReadPressureSome(resource string) (float64, error) {
	if resource != "cpu" && resource != "memory" && resource != "io" {
		return 0, errors.New("неизвестный ресурс давления")
	}
	raw, err := os.ReadFile("/proc/pressure/" + resource) //nolint:gosec
	if err != nil {
		return 0, err
	}
	return ParsePressureSome(raw)
}

func ReadLinkSpeed(iface string) (float64, bool) {
	if iface == "" || strings.ContainsAny(iface, "/\\ .") || len(iface) > 15 {
		return 0, false
	}
	raw, err := os.ReadFile("/sys/class/net/" + iface + "/speed") //nolint:gosec
	if err != nil {
		return 0, false
	}
	return ParseLinkSpeed(raw)
}
