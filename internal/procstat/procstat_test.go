package procstat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCPUAndBusy(t *testing.T) {
	a, err := ParseCPU([]byte("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n"))
	if err != nil || a.Busy != 150 || a.Total != 1000 {
		t.Fatalf("%+v %v", a, err)
	}
	b := CPUTimes{Busy: 250, Total: 1200}
	if v, ok := BusyPercent(a, b); !ok || v != 50 {
		t.Fatalf("занятость %v %v", v, ok)
	}
	if _, ok := BusyPercent(b, a); ok {
		t.Fatal("счётчики назад — должно быть неизвестно")
	}
	if _, err := ParseCPU([]byte("intr 1 2 3\n")); err == nil {
		t.Fatal("без строки cpu принято")
	}
}

func TestParsers(t *testing.T) {
	if v, err := ParseLoad1([]byte("0.42 0.30 0.20 1/300 12345\n")); err != nil || v != 0.42 {
		t.Fatalf("load1 %v %v", v, err)
	}
	if v, err := ParseMemUsedPercent([]byte("MemTotal:       1000 kB\nMemFree:  100 kB\nMemAvailable:    250 kB\n")); err != nil || v != 75 {
		t.Fatalf("mem %v %v", v, err)
	}
	if _, err := ParseMemUsedPercent([]byte("MemFree: 1 kB\n")); err == nil {
		t.Fatal("без MemTotal принято")
	}
	if v, err := ParsePressureSome([]byte("some avg10=3.37 avg60=1.17 avg300=0.27 total=1\nfull avg10=3.29 avg60=1 avg300=0 total=1\n")); err != nil || v != 3.37 {
		t.Fatalf("psi %v %v", v, err)
	}
	if _, err := ParsePressureSome([]byte("full avg10=1\n")); err == nil {
		t.Fatal("без some принято")
	}
	if v, ok := ParseLinkSpeed([]byte("1000\n")); !ok || v != 1000 {
		t.Fatalf("speed %v %v", v, ok)
	}
	if _, ok := ParseLinkSpeed([]byte("-1\n")); ok {
		t.Fatal("−1 у виртуальной карты — неизвестно")
	}
	if _, ok := ReadLinkSpeed("../../etc/passwd"); ok {
		t.Fatal("путь ушёл из /sys/class/net")
	}
}

func TestMemInfoBreakdown(t *testing.T) {
	m, err := ParseMemInfo([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\nBuffers: 50 kB\nCached: 400 kB\nSReclaimable: 30 kB\nShmem: 80 kB\nSwapTotal: 2000 kB\nSwapFree: 1500 kB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.UsedPercent() != 40 || m.CachePercent() != 40 {
		t.Fatalf("программы %v кэш %v", m.UsedPercent(), m.CachePercent())
	}
	if v, ok := m.SwapPercent(); !ok || v != 25 {
		t.Fatalf("swap %v %v", v, ok)
	}

	m, _ = ParseMemInfo([]byte("MemTotal: 1000 kB\nMemAvailable: 200 kB\nCached: 900 kB\n"))
	if m.UsedPercent()+m.CachePercent() > 100 {
		t.Fatalf("разбивка больше ста: %v + %v", m.UsedPercent(), m.CachePercent())
	}
	if _, ok := m.SwapPercent(); ok {
		t.Fatal("swap не настроен — должно быть неизвестно")
	}
}

func TestDiskBusy(t *testing.T) {
	raw := []byte("   8       0 sda 100 0 0 0 0 0 0 0 0 5000 0\n   8       1 sda1 1 0 0 0 0 0 0 0 0 9999 0\n 259 0 nvme0n1 1 0 0 0 0 0 0 0 0 200 0\n")
	got := ParseDiskTicks(raw, []string{"sda", "nvme0n1"})
	if len(got) != 2 || got["sda"] != 5000 || got["nvme0n1"] != 200 {
		t.Fatalf("тики %v", got)
	}
	if v, ok := DiskBusyPercent(map[string]uint64{"sda": 4500, "nvme0n1": 100}, got, 1000); !ok || v != 50 {
		t.Fatalf("занятость %v %v", v, ok)
	}
	if v, _ := DiskBusyPercent(map[string]uint64{"sda": 0}, got, 1000); v != 100 {
		t.Fatalf("занятость выше ста не ограничена: %v", v)
	}
	if _, ok := DiskBusyPercent(nil, got, 1000); ok {
		t.Fatal("первый снимок — должно быть неизвестно")
	}
}

func TestCPUTemp(t *testing.T) {
	write := func(root, rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	write(root, "sys/class/hwmon/hwmon0/name", "iwlwifi_1\n")
	write(root, "sys/class/hwmon/hwmon0/temp1_input", "39000\n")
	write(root, "sys/class/hwmon/hwmon1/name", "coretemp\n")
	write(root, "sys/class/hwmon/hwmon1/temp1_input", "48000\n")
	write(root, "sys/class/hwmon/hwmon1/temp1_crit", "100000\n")
	if got, ok := ReadCPUTempAt(root); !ok || got != (Temp{Cur: 48, Crit: 100}) {
		t.Fatalf("hwmon %+v %v", got, ok)
	}
	zones := t.TempDir()
	write(zones, "sys/class/thermal/thermal_zone0/type", "acpitz\n")
	write(zones, "sys/class/thermal/thermal_zone0/temp", "27800\n")
	write(zones, "sys/class/thermal/thermal_zone1/type", "x86_pkg_temp\n")
	write(zones, "sys/class/thermal/thermal_zone1/temp", "52000\n")
	write(zones, "sys/class/thermal/thermal_zone1/trip_point_0_type", "passive\n")
	write(zones, "sys/class/thermal/thermal_zone1/trip_point_0_temp", "90000\n")
	write(zones, "sys/class/thermal/thermal_zone1/trip_point_1_type", "critical\n")
	write(zones, "sys/class/thermal/thermal_zone1/trip_point_1_temp", "105000\n")
	if got, ok := ReadCPUTempAt(zones); !ok || got != (Temp{Cur: 52, Crit: 105}) {
		t.Fatalf("зона %+v %v", got, ok)
	}

	board := t.TempDir()
	write(board, "sys/class/thermal/thermal_zone0/type", "acpitz\n")
	write(board, "sys/class/thermal/thermal_zone0/temp", "27800\n")
	if got, ok := ReadCPUTempAt(board); ok {
		t.Fatalf("датчик платы принят за процессор: %+v", got)
	}
}
