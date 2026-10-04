package vpn

import "testing"

func TestCheckBelongsToItsSession(t *testing.T) {
	st := &Status{Mode: ModeBlack, Slug: "openvpn-stend"}
	st.Session.ID = 7
	cases := []struct {
		name string
		tun  CheckTunnel
		want bool
	}{
		{"тот же сеанс, профиль и режим", CheckTunnel{Profile: "openvpn-stend", Mode: ModeBlack, Session: 7}, true},
		{"прошлый сеанс", CheckTunnel{Profile: "openvpn-stend", Mode: ModeBlack, Session: 6}, false},
		{"другой профиль", CheckTunnel{Profile: "de-test1", Mode: ModeBlack, Session: 7}, false},
		{"другой режим", CheckTunnel{Profile: "openvpn-stend", Mode: ModeWhite, Session: 7}, false},
		{"сеанс сменился посреди проверки или строка старая", CheckTunnel{Profile: "openvpn-stend", Mode: ModeBlack}, false},
	}
	for _, c := range cases {
		if got := c.tun.Current(st); got != c.want {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}

	old := &Status{Mode: ModeBlack, Slug: "openvpn-stend"}
	if (CheckTunnel{Profile: "openvpn-stend", Mode: ModeBlack}).Current(old) {
		t.Error("нулевой сеанс с обеих сторон признан текущим")
	}
	if (CheckTunnel{Profile: "openvpn-stend", Mode: ModeBlack, Session: 7}).Current(nil) {
		t.Error("без состояния канала отчёт не может быть текущим")
	}
}
