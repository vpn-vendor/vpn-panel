package voicescore

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestScoreReferencePoints(t *testing.T) {
	cases := []struct {
		name           string
		rtt, jit, loss float64
		mos            float64
		level          Level
	}{
		{"идеальный", 0, 0, 0, 4.41, Good},
		{"VPN 24 мс", 24, 3, 0.1, 4.39, Good},
		{"потери 6 %", 30, 5, 6, 3.90, Good},
		{"потери 12 %", 30, 5, 12, 3.20, Fair},
		{"потери 15 %", 30, 5, 15, 2.81, Poor},
		{"300 мс", 300, 20, 0, 3.61, Good},
		{"400 мс", 400, 20, 0, 3.11, Fair},
	}
	for _, c := range cases {
		m, l := Score(c.rtt, c.jit, c.loss)
		if !near(m, c.mos) || l != c.level {
			t.Errorf("%s: оценка %.2f уровень %d, ждали %.2f и %d", c.name, m, l, c.mos, c.level)
		}
	}
}

func TestScoreIsBoundedAndMonotonic(t *testing.T) {
	if m, l := Score(5000, 500, 100); m != 1 || l != Poor {
		t.Fatalf("худший канал: %v %v", m, l)
	}
	prev := 5.0
	for loss := 0.0; loss <= 40; loss += 2 {
		m, _ := Score(40, 5, loss)
		if m > prev {
			t.Fatalf("потери растут, а оценка выросла: %v > %v при %v %%", m, prev, loss)
		}
		prev = m
	}
	if !(Threshold(GoodR) > Threshold(PoorR)) {
		t.Fatal("граница «хорошо» ниже границы «плохо»")
	}
}
