package cgroupstat

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMinLimitAcrossHierarchy(t *testing.T) {
	cases := []struct {
		name string
		raws []string
		want uint64
		ok   bool
	}{
		{"своя группа с пределом, родители без", []string{"402653184\n", "max\n", "max\n"}, 402653184, true},
		{"родитель строже", []string{"402653184\n", "268435456\n", "max\n"}, 268435456, true},
		{"предела нет нигде", []string{"max\n", "max\n"}, 0, false},
		{"мусор пропускается", []string{"мусор\n", "0\n", "1048576\n"}, 1048576, true},
		{"пусто", nil, 0, false},
	}
	for _, c := range cases {
		got, ok := minLimit(c.raws)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %d,%v; ожидалось %d,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestSoftLimitRatioAndFloor(t *testing.T) {

	if got := SoftMemoryLimit(384 << 20); got>>20 != 345 {
		t.Fatalf("0,9 от 384 МиБ = %d байт (%d МиБ), ожидалось 345 МиБ", got, got>>20)
	}
	if got := SoftMemoryLimit(64 << 20); got != SoftFloor {
		t.Fatalf("ниже пола предел не опускается: %d", got)
	}
	if SoftRatio != 0.9 || SoftFloor != 100<<20 {
		t.Fatal("доля и пол утверждены владельцем — менять только решением")
	}
}

func TestUnitCarriesNoHandwrittenSoftLimit(t *testing.T) {
	data, err := os.ReadFile("../../debian/vpn-panel.vpn-panel.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "GOMEMLIMIT") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("в юните рукописный мягкий предел: %q", line)
		}
	}
	if !strings.Contains(string(data), "MemoryMax=") {
		t.Fatal("в юните нет MemoryMax — мягкий предел не из чего выводить")
	}

	m := regexp.MustCompile(`(?m)^MemoryMax=(\S+)`).FindStringSubmatch(string(data))
	if m == nil || !strings.HasSuffix(m[1], "%") {
		t.Fatalf("MemoryMax обязан быть долей ОЗУ (проценты), а не константой: %q", m)
	}
}
