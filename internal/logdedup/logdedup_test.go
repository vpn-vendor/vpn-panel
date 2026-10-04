package logdedup

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func lines(b *bytes.Buffer) []string {
	s := strings.TrimRight(b.String(), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestBurstThenSummary(t *testing.T) {
	var out bytes.Buffer
	c := &clock{t: time.Unix(1000, 0)}
	w := newWriter(&out, 5*time.Second, 10, 512, c.now)

	for i := 0; i < 25; i++ {
		_, _ = w.Write([]byte("агент не отвечает\n"))
	}
	if got := len(lines(&out)); got != 10 {
		t.Fatalf("в окне записано %d строк, ожидалось 10", got)
	}

	c.t = c.t.Add(5 * time.Second)
	_, _ = w.Write([]byte("агент не отвечает\n"))
	got := lines(&out)
	if len(got) != 12 {
		t.Fatalf("после окна: %d строк, ожидалось 12 (сводка + строка): %q", len(got), got)
	}
	if !strings.Contains(got[10], "повторено ещё 15 раз") {
		t.Fatalf("нет сводки о подавленных: %q", got[10])
	}
}

func TestDifferentLinesAreIndependent(t *testing.T) {
	var out bytes.Buffer
	c := &clock{t: time.Unix(1000, 0)}
	w := newWriter(&out, 5*time.Second, 2, 512, c.now)
	for i := 0; i < 5; i++ {
		_, _ = w.Write([]byte("а\n"))
		_, _ = w.Write([]byte("б\n"))
	}
	if got := len(lines(&out)); got != 4 {
		t.Fatalf("две строки по два раза = 4, записано %d", got)
	}
}

func TestSummaryOnOtherLineAfterWindow(t *testing.T) {
	var out bytes.Buffer
	c := &clock{t: time.Unix(1000, 0)}
	w := newWriter(&out, 5*time.Second, 1, 512, c.now)
	for i := 0; i < 4; i++ {
		_, _ = w.Write([]byte("лавина\n"))
	}
	c.t = c.t.Add(6 * time.Second)
	_, _ = w.Write([]byte("редкое\n"))
	if !strings.Contains(out.String(), "повторено ещё 3 раз за 5s: лавина") {
		t.Fatalf("сводка не выпущена: %q", out.String())
	}
}

func TestKeysCeiling(t *testing.T) {
	var out bytes.Buffer
	c := &clock{t: time.Unix(1000, 0)}
	w := newWriter(&out, 5*time.Second, 10, 8, c.now)
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte("адрес " + strconv.Itoa(i) + "\n"))
	}
	if w.Keys() > 8 {
		t.Fatalf("учёт вырос до %d при потолке 8", w.Keys())
	}
	if got := len(lines(&out)); got != 100 {
		t.Fatalf("уникальные строки потеряны: записано %d из 100", got)
	}
}

func TestApprovedNumbers(t *testing.T) {
	if Window != 5*time.Second || Burst != 10 || MaxKeys != 512 {
		t.Fatalf("числа сведения изменены: %v %d %d", Window, Burst, MaxKeys)
	}
}
