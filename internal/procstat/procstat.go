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

func ParseMemUsedPercent(raw []byte) (float64, error) {
	var total, avail uint64
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
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 || avail > total {
		return 0, errors.New("в /proc/meminfo нет MemTotal или MemAvailable")
	}
	return 100 * float64(total-avail) / float64(total), nil
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
