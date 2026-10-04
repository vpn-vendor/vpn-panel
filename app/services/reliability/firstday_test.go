package reliability

import (
	"strconv"
	"testing"
	"time"
)

func TestFirstDayWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(-d).Unix(), 10) }
	cases := []struct {
		raw  string
		want bool
	}{
		{at(time.Minute), true},
		{at(FirstDayFor - time.Minute), true},
		{at(FirstDayFor), false},
		{at(30 * 24 * time.Hour), false},
		{at(-time.Hour), false},
		{"", false},
		{"мусор", false},
	}
	for _, c := range cases {
		if got := firstDay(c.raw, now); got != c.want {
			t.Errorf("%q: %v, ожидалось %v", c.raw, got, c.want)
		}
	}
}
