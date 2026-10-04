package cgroupstat

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func CPUPressure() (someAvg10 float64, ok bool) {
	data, err := os.ReadFile(selfCgroup)
	if err != nil {
		return 0, false
	}
	p, ok := unifiedPath(data)
	if !ok {
		return 0, false
	}
	raw, err := os.ReadFile(filepath.Join(cgroupRoot, p, "cpu.pressure")) //nolint:gosec
	if err != nil {
		return 0, false
	}
	return pressureSomeAvg10(raw)
}

func pressureSomeAvg10(raw []byte) (float64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "some" {
			continue
		}
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "avg10=") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
			if err != nil || v < 0 || v > 100 {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}
