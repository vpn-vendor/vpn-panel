package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseCPUOnRealDumps(t *testing.T) {
	stand := ParseCPU(fixture(t, "cpuinfo-vm.txt"))
	if stand.Model != "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz" {
		t.Errorf("модель виртуальной машины: %q", stand.Model)
	}
	if stand.Threads != 2 || stand.Cores != 2 {
		t.Errorf("виртуальная машина: потоков %d, ядер %d — у двух процессоров по одному ядру это 2 и 2", stand.Threads, stand.Cores)
	}
	if !stand.CryptoFast {
		t.Error("виртуальная машина: ускорение шифрования обязано определяться по флагу aes")
	}

	multi := ParseCPU(fixture(t, "cpuinfo-desktop.txt"))
	if multi.Threads != 4 || multi.Cores != 2 {
		t.Errorf("многопоточный: потоков %d, ядер %d, ждали 4 и 2", multi.Threads, multi.Cores)
	}
	if !multi.CryptoFast {
		t.Error("многопоточный: флаг aes есть, ускорение обязано определяться")
	}

	weak := ParseCPU(fixture(t, "cpuinfo-noaes.txt"))
	if weak.CryptoFast {
		t.Error("без флага aes ускорения шифрования нет")
	}
	if weak.Model == "" || weak.Cores != 2 {
		t.Errorf("слабый: %+v", weak)
	}
}

func TestParseMemoryAndSystem(t *testing.T) {
	if got := ParseMemTotal(fixture(t, "meminfo-vm.txt")); got != 3480272*1024 {
		t.Errorf("память: %d байт", got)
	}
	if got := ParseMemTotal([]byte("MemFree: 1 kB\n")); got != 0 {
		t.Errorf("без строки объёма память обязана быть неизвестна: %d", got)
	}
	if got := ParseOSName(fixture(t, "os-release-vm.txt")); got != "Ubuntu 26.04.1 LTS" {
		t.Errorf("система: %q", got)
	}
	if got := ParseOSName([]byte("ID=ubuntu\n")); got != "" {
		t.Errorf("без человеческого названия обязана быть пустота: %q", got)
	}
}

func TestParseUptime(t *testing.T) {
	now := time.Date(2026, 9, 18, 17, 0, 0, 0, time.UTC)
	b, ok := ParseUptime([]byte("18646.90 36643.47\n"), now)
	if !ok || b.For.Round(time.Second) != 18647*time.Second {
		t.Errorf("время работы: %v (%v)", b.For, ok)
	}
	if b.Since.After(now) {
		t.Error("момент загрузки не может быть в будущем")
	}
	if _, ok := ParseUptime([]byte("мусор\n"), now); ok {
		t.Error("мусор обязан давать «неизвестно», а не ноль секунд работы")
	}
}

func TestDiskKindNeverGuesses(t *testing.T) {
	cases := []struct {
		name, rotational, model, want string
	}{
		{"nvme0n1", "0", "Samsung SSD 980", "NVMe"},
		{"sda", "0", "Samsung SSD 870", "SSD"},
		{"sda", "1", "WDC WD10EZEX", "жёсткий диск"},
		{"vda", "1", "", ""},
		{"sdb", "1", "", ""},
		{"sdc", "", "Some", ""},
	}
	for _, c := range cases {
		if got := diskKind(c.name, c.rotational, c.model); got != c.want {
			t.Errorf("%s (вращение %q, модель %q): %q, ждали %q", c.name, c.rotational, c.model, got, c.want)
		}
	}
}

func TestPortsSayUnknownInsteadOfZero(t *testing.T) {
	dir := t.TempDir()
	Root = dir
	defer func() { Root = "/" }()
	mk := func(name, speed, duplex string) {
		base := filepath.Join(dir, "sys/class/net", name)
		if err := os.MkdirAll(base, 0o750); err != nil {
			t.Fatal(err)
		}
		for file, val := range map[string]string{"speed": speed, "duplex": duplex} {
			if val == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(base, file), []byte(val+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("ens3", "-1", "unknown")
	mk("ens4", "1000", "full")
	mk("ovpn-vpn0", "", "")

	ports := Ports([]string{"ens3", "ens4", "ovpn-vpn0", ""})
	if len(ports) != 3 {
		t.Fatalf("портов %d, пустое имя обязано отбрасываться", len(ports))
	}
	if ports[0].SpeedKnown || ports[0].SpeedMbit != 0 || ports[0].Duplex != "" {
		t.Errorf("виртуальная карта обязана давать «неизвестно»: %+v", ports[0])
	}
	if !ports[1].SpeedKnown || ports[1].SpeedMbit != 1000 || ports[1].Duplex != "full" {
		t.Errorf("настоящая карта: %+v", ports[1])
	}
	if ports[2].SpeedKnown {
		t.Errorf("карта без файлов скорости: %+v", ports[2])
	}
}

func TestParseBootID(t *testing.T) {
	if id, ok := ParseBootID([]byte("fbd6b15a-8fce-4686-98a0-faab789f7f22\n")); !ok || id != "fbd6b15a-8fce-4686-98a0-faab789f7f22" {
		t.Fatalf("настоящий идентификатор не принят: %q %v", id, ok)
	}
	for _, bad := range []string{"", "\n", "fbd6b15a8fce468698a0faab789f7f22", "FBD6B15A-8FCE-4686-98A0-FAAB789F7F22", "fbd6b15a-8fce-4686-98a0-faab789f7f2z"} {
		if _, ok := ParseBootID([]byte(bad)); ok {
			t.Errorf("%q принят как идентификатор загрузки", bad)
		}
	}
}
