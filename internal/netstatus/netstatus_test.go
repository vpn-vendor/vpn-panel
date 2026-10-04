package netstatus

import (
	"testing"
)

const addrFixture = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","group":"default","txqlen":1000,"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo","valid_life_time":4294967295,"preferred_life_time":4294967295},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host","valid_life_time":4294967295,"preferred_life_time":4294967295}]},{"ifindex":2,"link_index":182,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","link_type":"ether","address":"d2:6e:60:bf:5e:9f","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":0,"addr_info":[{"family":"inet","local":"172.17.0.3","prefixlen":16,"broadcast":"172.17.255.255","scope":"global","label":"eth0","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]`

const routeFixture = `[{"dst":"default","gateway":"172.17.0.1","dev":"eth0","flags":[]},{"dst":"172.17.0.0/16","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.3","flags":[]}]`

func TestParseRealFixtures(t *testing.T) {
	s, err := Parse([]byte(addrFixture), []byte(routeFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(s.Interfaces) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(s.Interfaces))
	}

	lo := s.Interfaces[0]
	if lo.Name != "lo" || !lo.Loopback || lo.MAC != "" {
		t.Fatalf("bad loopback: %+v", lo)
	}
	if len(lo.Addresses) != 2 || lo.Addresses[0] != "127.0.0.1/8" {
		t.Fatalf("bad lo addresses: %v", lo.Addresses)
	}

	eth := s.Interfaces[1]
	if eth.Name != "eth0" || eth.Loopback || eth.MAC != "d2:6e:60:bf:5e:9f" {
		t.Fatalf("bad eth0: %+v", eth)
	}
	if eth.State != "UP" || eth.MTU != 1500 {
		t.Fatalf("bad eth0 state/mtu: %+v", eth)
	}
	if len(eth.Addresses) != 1 || eth.Addresses[0] != "172.17.0.3/16" {
		t.Fatalf("bad eth0 addresses: %v", eth.Addresses)
	}

	if len(s.DefaultRoutes) != 1 {
		t.Fatalf("want 1 default route, got %d", len(s.DefaultRoutes))
	}
	r := s.DefaultRoutes[0]
	if r.Via != "172.17.0.1" || r.Dev != "eth0" {
		t.Fatalf("bad default route: %+v", r)
	}
}

func TestParseEmpty(t *testing.T) {
	s, err := Parse([]byte(`[]`), []byte(`[]`))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(s.Interfaces) != 0 || len(s.DefaultRoutes) != 0 {
		t.Fatalf("want empty status, got %+v", s)
	}
}

func TestParseBadJSON(t *testing.T) {
	if _, err := Parse([]byte(`{broken`), []byte(`[]`)); err == nil {
		t.Fatal("want error on broken addr json")
	}
	if _, err := Parse([]byte(`[]`), []byte(`{broken`)); err == nil {
		t.Fatal("want error on broken route json")
	}
}

func TestCollectOnRealSystem(t *testing.T) {

	if _, err := findIPBinary(); err != nil {
		t.Skip("iproute2 not installed")
	}
	s, err := Collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(s.Interfaces) == 0 {
		t.Fatal("want at least loopback interface")
	}
}
