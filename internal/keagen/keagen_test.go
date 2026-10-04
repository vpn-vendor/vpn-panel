package keagen

import (
	"encoding/json"
	"strings"
	"testing"
)

func known() map[string]bool { return map[string]bool{"ens4": true, "ens5": true} }

func TestPoolForCommonSubnets(t *testing.T) {
	cases := []struct{ cidr, start, end string }{
		{"192.168.77.1/24", "192.168.77.100", "192.168.77.200"},
		{"10.10.0.1/24", "10.10.0.100", "10.10.0.200"},
		{"192.168.5.1/23", "192.168.4.100", "192.168.4.200"},
	}
	for _, c := range cases {
		s, e, err := PoolFor(c.cidr)
		if err != nil {
			t.Fatalf("%s: %v", c.cidr, err)
		}
		if s.String() != c.start || e.String() != c.end {
			t.Fatalf("%s: got %s–%s, want %s–%s", c.cidr, s, e, c.start, c.end)
		}
	}
}

func TestPoolForNarrowSubnet(t *testing.T) {

	s, e, err := PoolFor("192.168.1.1/26")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipToUint(s) <= ipToUint(e) == false {
		t.Fatal("bad range")
	}
	if s.String() != "192.168.1.31" || e.String() != "192.168.1.62" {
		t.Fatalf("got %s–%s", s, e)
	}
	if PoolSize("192.168.1.1/26") != 32 {
		t.Fatalf("pool size: %d", PoolSize("192.168.1.1/26"))
	}
}

func TestPoolTooSmall(t *testing.T) {
	if _, _, err := PoolFor("192.168.1.1/31"); err == nil {
		t.Fatal("want error for /31")
	}
}

func TestGenerateDeterministicAndComplete(t *testing.T) {
	a := Plan{LANs: []LAN{
		{Name: "ens5", CIDR: "10.10.0.1/24"},
		{Name: "ens4", CIDR: "192.168.77.1/24"},
	}}
	if err := a.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out, err := a.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b := Plan{LANs: []LAN{a.LANs[1], a.LANs[0]}}
	out2, _ := b.Generate()
	if string(out) != string(out2) {
		t.Fatal("output must not depend on input order")
	}

	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("config is not valid json: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"valid-lifetime": 345600`,
		`"renew-timer": 172800`,
		`"rebind-timer": 302400`,
		`"decline-probation-period": 3600`,
		`"service-sockets-max-retries": 20`,
		`192.168.77.100 - 192.168.77.200`,
		`"ens4"`,
		`"name": "routers"`,
		`"name": "ntp-servers"`,
		`"name": "domain-name"`,
		LocalDomain,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("config lacks %q:\n%s", want, s)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		plan Plan
	}{
		{"empty", Plan{}},
		{"unknown nic", Plan{LANs: []LAN{{Name: "eth9", CIDR: "192.168.1.1/24"}}}},
		{"bad name", Plan{LANs: []LAN{{Name: "a b", CIDR: "192.168.1.1/24"}}}},
		{"dup", Plan{LANs: []LAN{
			{Name: "ens4", CIDR: "192.168.1.1/24"},
			{Name: "ens4", CIDR: "192.168.2.1/24"},
		}}},
		{"bad cidr", Plan{LANs: []LAN{{Name: "ens4", CIDR: "not-an-ip"}}}},

		{"gw in pool", Plan{LANs: []LAN{{Name: "ens4", CIDR: "192.168.77.150/24"}}}},
		{"subnet too small", Plan{LANs: []LAN{{Name: "ens4", CIDR: "192.168.1.1/31"}}}},
	}
	for _, c := range cases {
		if err := c.plan.Validate(known()); err == nil {
			t.Fatalf("%s: want error", c.name)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"A4-BB-6D-1F-22-90":  "a4:bb:6d:1f:22:90",
		"a4bb.6d1f.2290":     "a4:bb:6d:1f:22:90",
		"A4:BB:6D:1F:22:90":  "a4:bb:6d:1f:22:90",
		" a4 bb 6d 1f 22 90": "a4:bb:6d:1f:22:90",
	}
	for in, want := range cases {
		got, err := NormalizeMAC(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %q (%v), want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "aabbcc", "не-адрес", "a4:bb:6d:1f:22:90:11"} {
		if _, err := NormalizeMAC(bad); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

func TestIsRandomMAC(t *testing.T) {

	for _, mac := range []string{"a2:bb:6d:1f:22:90", "8e:00:11:22:33:44", "06:11:22:33:44:55"} {
		if !IsRandomMAC(mac) {
			t.Fatalf("%s: должен опознаваться как случайный", mac)
		}
	}
	for _, mac := range []string{"a4:bb:6d:1f:22:90", "00:1a:2b:3c:4d:5e", "d8:cb:8a:11:22:33"} {
		if IsRandomMAC(mac) {
			t.Fatalf("%s: не случайный", mac)
		}
	}
}

func TestReservationRangeOutsidePool(t *testing.T) {
	rs, re, err := ReservationRange("192.168.77.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if rs.String() != "192.168.77.20" || re.String() != "192.168.77.99" {
		t.Fatalf("got %s–%s", rs, re)
	}
	ps, _, _ := PoolFor("192.168.77.1/24")
	if ipToUint(re) >= ipToUint(ps) {
		t.Fatal("диапазон закреплений не должен пересекаться с пулом")
	}
}

func TestValidateReservationIP(t *testing.T) {
	cidr := "192.168.77.1/24"
	if err := ValidateReservationIP(cidr, "192.168.77.50"); err != nil {
		t.Fatalf("валидный адрес отклонён: %v", err)
	}
	bad := map[string]string{
		"шлюз":          "192.168.77.1",
		"внутри пула":   "192.168.77.150",
		"чужая подсеть": "10.0.0.5",
		"адрес сети":    "192.168.77.0",
		"широковещание": "192.168.77.255",
		"не адрес":      "не-адрес",
	}
	for name, ip := range bad {
		if err := ValidateReservationIP(cidr, ip); err == nil {
			t.Fatalf("%s (%s): ожидалась ошибка", name, ip)
		}
	}
}

func TestGenerateWithReservations(t *testing.T) {
	p := Plan{LANs: []LAN{{
		Name: "ens4", CIDR: "192.168.77.1/24",
		Reservations: []Reservation{
			{MAC: "a4:bb:6d:1f:22:91", IP: "192.168.77.51"},
			{MAC: "a4:bb:6d:1f:22:90", IP: "192.168.77.50"},
		},
	}}}
	out, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"hw-address": "a4:bb:6d:1f:22:90"`) || !strings.Contains(s, `"ip-address": "192.168.77.50"`) {
		t.Fatalf("резервации не попали в конфигурацию:\n%s", s)
	}

	p2 := Plan{LANs: []LAN{{Name: "ens4", CIDR: "192.168.77.1/24",
		Reservations: []Reservation{p.LANs[0].Reservations[1], p.LANs[0].Reservations[0]}}}}
	out2, _ := p2.Generate()
	if string(out) != string(out2) {
		t.Fatal("порядок резерваций не должен влиять на результат")
	}
}

func TestClientDNSSwitch(t *testing.T) {
	base := Plan{LANs: []LAN{{Name: "ens4", CIDR: "192.168.77.1/24"}}}
	pub, _ := base.Generate()
	if !strings.Contains(string(pub), `"data": "9.9.9.9, 149.112.112.112"`) {
		t.Fatalf("до проверки резолвера клиентам раздаются публичные адреса:\n%s", pub)
	}
	local := Plan{LANs: base.LANs, UseLocalDNS: true}
	out, _ := local.Generate()
	if !strings.Contains(string(out), `"name": "domain-name-servers"`) ||
		!strings.Contains(string(out), `"data": "192.168.77.1"`) {
		t.Fatalf("после проверки клиентам раздаётся адрес шлюза:\n%s", out)
	}
}
