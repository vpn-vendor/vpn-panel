package procstat

import "testing"

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
