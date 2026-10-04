package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestUptimeIsParsedAsBootTime(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"12345.67 98765.43\n", 12345670 * time.Millisecond, true},
		{"0.00 0.00", 0, true},
		{"  4242.10   1.0  \n", 4242100 * time.Millisecond, true},
		{"", 0, false},
		{"мусор 1.0", 0, false},
		{"-1.0 2.0", 0, false},
	} {
		got, ok := parseUptime(c.in)
		if ok != c.ok {
			t.Fatalf("%q: разобрано=%v, ждали %v", c.in, ok, c.ok)
		}
		if ok && got != c.want {
			t.Fatalf("%q: %s, ждали %s", c.in, got, c.want)
		}
	}
}

func TestUnknownAgeIsNotZero(t *testing.T) {
	if got := sinceBoot(0, "boot-a"); got != -1 {
		t.Fatalf("пустая отметка обязана давать «не знаю»: %d", got)
	}
	if got := sinceBoot(bootInstant(time.Minute), "заведомо-чужая-загрузка"); got != -1 {
		t.Fatalf("отметка из другой загрузки обязана давать «не знаю»: %d", got)
	}
}

func TestDueRespectsDeadline(t *testing.T) {
	if !due(0) {
		t.Fatal("неназначенный срок обязан означать «пора»")
	}
	if now, ok := bootNow(); ok {
		if due(now.Add(time.Hour)) {
			t.Fatal("срок через час не наступил, а попытка разрешена")
		}
		if !due(now.Add(-time.Second)) {
			t.Fatal("срок в прошлом обязан разрешать попытку")
		}
	}
}

func TestTransmittedBytesNeverJudgeTheLink(t *testing.T) {
	files := []string{"vpn_watchdog.go", "vpn_probe.go"}
	bad := regexp.MustCompile(`TxBytes`)
	for _, name := range files {
		data, err := os.ReadFile(name) //nolint:gosec
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if loc := bad.FindIndex(data); loc != nil {
			line := 1 + strings.Count(string(data[:loc[0]]), "\n")
			t.Fatalf("%s:%d — переданные байты не могут участвовать в суждении о канале", name, line)
		}
	}
}
