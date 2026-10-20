package procstat

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	cpuHwmon = map[string]bool{"coretemp": true, "k10temp": true, "zenpower": true, "cpu_thermal": true, "soc_thermal": true}
	cpuZones = map[string]bool{"x86_pkg_temp": true, "cpu-thermal": true, "cpu_thermal": true, "soc_thermal": true, "cpu": true}
)

type Temp struct {
	Cur, Crit float64
}

func ReadCPUTemp() (Temp, bool) { return ReadCPUTempAt("/") }

func ReadCPUTempAt(root string) (Temp, bool) {
	if t, ok := hwmonTemp(filepath.Join(root, "sys/class/hwmon")); ok {
		return t, true
	}
	return zoneTemp(filepath.Join(root, "sys/class/thermal"))
}

func hwmonTemp(dir string) (Temp, bool) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		d := filepath.Join(dir, e.Name())
		if !cpuHwmon[strings.TrimSpace(readSys(filepath.Join(d, "name")))] {
			continue
		}
		cur, ok := milli(readSys(filepath.Join(d, "temp1_input")))
		if !ok {
			continue
		}
		crit, ok := milli(readSys(filepath.Join(d, "temp1_crit")))
		if !ok {
			crit, _ = milli(readSys(filepath.Join(d, "temp1_max")))
		}
		return Temp{Cur: cur, Crit: crit}, true
	}
	return Temp{}, false
}

func zoneTemp(dir string) (Temp, bool) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		d := filepath.Join(dir, e.Name())
		if !cpuZones[strings.TrimSpace(readSys(filepath.Join(d, "type")))] {
			continue
		}
		cur, ok := milli(readSys(filepath.Join(d, "temp")))
		if !ok {
			continue
		}
		t := Temp{Cur: cur}
		for i := 0; ; i++ {
			kind := readSys(filepath.Join(d, "trip_point_"+strconv.Itoa(i)+"_type"))
			if kind == "" {
				break
			}
			if strings.TrimSpace(kind) == "critical" {
				t.Crit, _ = milli(readSys(filepath.Join(d, "trip_point_"+strconv.Itoa(i)+"_temp")))
			}
		}
		return t, true
	}
	return Temp{}, false
}

func milli(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	c := v / 1000
	if c <= 0 || c > 150 {
		return 0, false
	}
	return c, true
}

func readSys(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return ""
	}
	return string(b)
}
