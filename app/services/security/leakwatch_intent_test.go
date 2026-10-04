package security

import "testing"

func TestIntentLostOnce(t *testing.T) {
	cases := []struct{ was, now, want bool }{
		{false, false, false}, {false, true, true}, {true, true, false}, {true, false, false},
	}
	for _, c := range cases {
		if got := intentLost(c.was, c.now); got != c.want {
			t.Errorf("was=%v now=%v: %v, ожидалось %v", c.was, c.now, got, c.want)
		}
	}
}
