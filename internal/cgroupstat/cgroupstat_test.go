package cgroupstat

import "testing"

func TestUnifiedPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0::/system.slice/vpn-panel.service\n", "/system.slice/vpn-panel.service", true},
		{"12:cpu:/legacy\n0::/user.slice/session-4.scope\n", "/user.slice/session-4.scope", true},
		{"12:cpu:/legacy\n", "", false},
		{"0::relative\n", "", false},
		{"0::/../../etc\n", "", false},
	}
	for _, c := range cases {
		got, ok := unifiedPath([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("%q → %q,%v; ожидалось %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestThrottledUsec(t *testing.T) {
	withQuota := "usage_usec 16476128\nuser_usec 12507641\nsystem_usec 3968486\nnr_periods 120\nnr_throttled 7\nthrottled_usec 351000\n"
	if v, ok := throttledUsec([]byte(withQuota)); !ok || v != 351000 {
		t.Fatalf("с потолком: %d,%v", v, ok)
	}
	noQuota := "usage_usec 16476128\nuser_usec 12507641\nsystem_usec 3968486\nnice_usec 0\n"
	if _, ok := throttledUsec([]byte(noQuota)); ok {
		t.Fatal("без потолка ответ обязан быть «неизвестно»")
	}
	if _, ok := throttledUsec([]byte("throttled_usec мусор\n")); ok {
		t.Fatal("мусор не число")
	}
}
