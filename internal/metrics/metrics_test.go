package metrics

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTiersFrozen(t *testing.T) {
	if Tier0Step != time.Second || Tier0Len != 7200 || Tier1Step != 10*time.Second || Tier1Len != 8640 ||
		Tier2Step != time.Minute || Tier2Len != 10080 || MaxPoints != 4000 || FileVersion != 1 {
		t.Fatal("числа уровней, потолок точек или версия файла изменены")
	}
	if TierSpec[0].Agg || !TierSpec[1].Agg || !TierSpec[2].Agg {
		t.Fatal("уровень 0 хранит значение, грубые — минимум, среднее, максимум")
	}
}

func TestNoAppendOnHistory(t *testing.T) {
	re := regexp.MustCompile(`\bappend\(`)
	for _, f := range []string{"series.go", "query.go"} {
		src, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(src) {
			t.Fatalf("%s содержит append — история обязана быть кольцом", f)
		}
	}
}

func TestMemoryFixedAfterMillionSamples(t *testing.T) {
	s := New()
	l0, c0 := s.Len(), s.Cap()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 1_000_000; i++ {
		s.Add(base.Add(time.Duration(i)*time.Second), float64(i%100))
	}
	if s.Len() != l0 || s.Cap() != c0 {
		t.Fatalf("память выросла: %d/%d → %d/%d", l0, c0, s.Len(), s.Cap())
	}
	if want := Tier0Len + 2*Tier1Len*3 + 0; l0 != Tier0Len+Tier1Len*3+Tier2Len*3 {
		t.Fatalf("длина колец %d, ожидалось %d", l0, want)
	}
}

func TestRollupKeepsMinAvgMax(t *testing.T) {
	s := New()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 70; i++ {
		v := 10.0
		if i == 5 {
			v = 100
		}
		s.Add(base.Add(time.Duration(i)*time.Second), v)
	}
	p, ok := s.rings[1].at(s.rings[1].slot(base.Unix()))
	if !ok || p.Min != 10 || p.Max != 100 || math.Abs(p.Avg-19) > 1e-9 {
		t.Fatalf("уровень 1 первая ячейка: %+v %v", p, ok)
	}
	p2, ok := s.rings[2].at(s.rings[2].slot(base.Unix()))
	if !ok || p2.Max != 100 || p2.Min != 10 {
		t.Fatalf("уровень 2 первая ячейка: %+v %v — пик потерян", p2, ok)
	}
}

func TestGapIsUnknown(t *testing.T) {
	s := New()
	base := time.Unix(1_700_000_000, 0)
	s.Add(base, 1)
	s.Add(base.Add(5*time.Second), 2)
	p, ok := s.rings[0].at(base.Unix() + 2)
	if !ok || !math.IsNaN(p.Avg) {
		t.Fatalf("пропущенная секунда: %+v %v", p, ok)
	}
	if p, _ := s.rings[0].at(base.Unix() + 5); p.Avg != 2 {
		t.Fatal("отсчёт после пропуска потерян")
	}
}

func TestRangeNeverExceedsWidth(t *testing.T) {
	s := New()
	now := time.Unix(1_700_000_000, 0).Add(8 * 24 * time.Hour)
	for i := 0; i < 8*24*3600; i += 7 {
		s.Add(now.Add(-time.Duration(8*24*3600-i)*time.Second), float64(i%50))
	}
	for _, c := range []struct {
		span  time.Duration
		width int
	}{{time.Hour, 800}, {2 * time.Hour, 100}, {24 * time.Hour, 1920}, {7 * 24 * time.Hour, 300}, {7 * 24 * time.Hour, 100000}, {10 * time.Minute, 1}} {
		from := now.Add(-c.span)
		p := PlanFor(now, from, now, c.width)
		pts := s.Range(p, from, now)
		limit := c.width
		if limit <= 0 || limit > MaxPoints {
			limit = MaxPoints
		}
		if len(pts) > limit || len(pts) > MaxPoints {
			t.Fatalf("окно %v ширина %d: точек %d > %d (план %+v)", c.span, c.width, len(pts), limit, p)
		}
		onLadder := false
		for _, l := range Ladder {
			onLadder = onLadder || l == p.Step
		}
		if !onLadder {
			t.Fatalf("шаг %v не с лестницы", p.Step)
		}
		if from.Before(now.Add(-TierSpec[p.Tier].Depth())) {
			t.Fatalf("уровень %d не покрывает окно %v", p.Tier, c.span)
		}
	}

	p := PlanFor(now, now.Add(-7*24*time.Hour), now, 168)
	pts := s.Range(p, now.Add(-7*24*time.Hour), now)
	maxSeen := 0.0
	for _, pt := range pts {
		if !math.IsNaN(pt.Max) && pt.Max > maxSeen {
			maxSeen = pt.Max
		}
	}
	if maxSeen < 49 {
		t.Fatalf("пик потерян при прореживании: максимум %v", maxSeen)
	}
}

func TestFileRoundTripAndRejects(t *testing.T) {
	s := New()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 600; i++ {
		s.Add(base.Add(time.Duration(i)*time.Second), float64(i))
	}
	s.Add(base.Add(601*time.Second), 0)
	var buf bytes.Buffer
	if err := Save(&buf, map[string]*Series{"cpu": s, "mem": New()}); err != nil {
		t.Fatal(err)
	}
	size := buf.Len()
	fresh := map[string]*Series{"cpu": New(), "other": New()}
	n, err := Load(bytes.NewReader(buf.Bytes()), fresh)
	if err != nil || n != 2 {
		t.Fatalf("восстановлено %d, %v", n, err)
	}
	want, _ := s.rings[1].at(s.rings[1].slot(base.Unix()))
	got, ok := fresh["cpu"].rings[1].at(s.rings[1].slot(base.Unix()))
	if !ok || got != want {
		t.Fatalf("уровень 1 после чтения: %+v, ожидалось %+v", got, want)
	}
	if fresh["cpu"].rings[0].last != 0 {
		t.Fatal("уровень 0 не должен читаться с диска")
	}

	for i := 600; i < 100_000; i++ {
		s.Add(base.Add(time.Duration(i)*time.Second), 1)
	}
	var buf2 bytes.Buffer
	_ = Save(&buf2, map[string]*Series{"cpu": s, "mem": New()})
	if buf2.Len() != size {
		t.Fatalf("файл вырос: %d → %d", size, buf2.Len())
	}

	bad := append([]byte(nil), buf.Bytes()...)
	bad[len(bad)-1] ^= 0xff
	if _, err := Load(bytes.NewReader(bad), map[string]*Series{"cpu": New()}); err == nil {
		t.Fatal("битая сумма принята")
	}
	if _, err := Load(strings.NewReader("не наш файл"), map[string]*Series{}); err == nil {
		t.Fatal("чужой файл принят")
	}
	ver := append([]byte(nil), buf.Bytes()...)
	ver[4] = 9
	if _, err := Load(bytes.NewReader(ver), map[string]*Series{"cpu": New()}); err == nil {
		t.Fatal("иная версия принята")
	}

	p := filepath.Join(t.TempDir(), "metrics.bin")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p) //nolint:gosec
	defer func() { _ = f.Close() }()
	if n, err := Load(f, map[string]*Series{"cpu": New()}); err != nil || n != 2 {
		t.Fatalf("чтение с диска: %d %v", n, err)
	}
}
