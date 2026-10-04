package network

import "testing"

func goodNetwork() Section {
	return Section{ConfirmTimeoutSec: 120, Interfaces: []SectionInterface{
		{Name: "enp1s0", MAC: "02:00:00:00:00:01", Role: "wan", IPv4Method: "static", IPv4CIDR: "203.0.113.45/24",
			IPv4Gateway: "203.0.113.1", IPv4DNS: "1.1.1.1, 9.9.9.9", WANMetric: 100},
		{Name: "enp2s0", MAC: "02:00:00:00:00:02", Role: "lan", IPv4Method: "static", IPv4CIDR: "192.168.11.1/24"},
		{Name: "enp3s0", MAC: "02:00:00:00:00:03", Role: "unused"},
	}}
}

func TestValidateSection(t *testing.T) {
	if errs := ValidateSection(goodNetwork()); len(errs) > 0 {
		t.Fatalf("годный раздел отвергнут: %v", errs.Err())
	}
	for _, c := range []struct {
		name string
		edit func(*Section)
		path string
	}{
		{"окно подтверждения", func(s *Section) { s.ConfirmTimeoutSec = 5 }, "confirm_timeout_sec"},
		{"имя карты", func(s *Section) { s.Interfaces[0].Name = "eth 0" }, "interfaces[0].name"},
		{"MAC не в каноне", func(s *Section) { s.Interfaces[0].MAC = "02-00-00-00-00-01" }, "interfaces[enp1s0].mac"},
		{"неизвестная роль", func(s *Section) { s.Interfaces[2].Role = "dmz" }, "interfaces[enp3s0].role"},
		{"способ WAN", func(s *Section) { s.Interfaces[0].IPv4Method = "l2tp" }, "interfaces[enp1s0].ipv4_method"},
		{"LAN не статика", func(s *Section) { s.Interfaces[1].IPv4Method = "dhcp" }, "interfaces[enp2s0].ipv4_method"},
		{"шлюз у LAN", func(s *Section) { s.Interfaces[1].IPv4Gateway = "192.168.11.254" }, "interfaces[enp2s0].ipv4_gateway"},
		{"DNS у DHCP", func(s *Section) { s.Interfaces[0].IPv4Method = "dhcp"; s.Interfaces[0].IPv4CIDR = "" }, "interfaces[enp1s0].ipv4_gateway"},
		{"логин PPPoE", func(s *Section) {
			s.Interfaces[0] = SectionInterface{Name: "enp1s0", Role: "wan", IPv4Method: "pppoe", PPPoEUsername: "user\"x"}
		}, "interfaces[enp1s0].pppoe_username"},
		{"тег VLAN", func(s *Section) { s.Interfaces[0].VLAN = 5000 }, "interfaces[enp1s0].vlan"},
		{"VLAN у LAN", func(s *Section) { s.Interfaces[1].VLAN = 10 }, "interfaces[enp2s0].vlan"},
		{"способ у неиспользуемой", func(s *Section) { s.Interfaces[2].IPv4Method = "dhcp" }, "interfaces[enp3s0].ipv4_method"},
		{"интерфейс очереди", func(s *Section) { s.Interfaces[2].Name = "ifb-vpn0" }, "interfaces[ifb-vpn0].name"},
		{"интерфейс канала", func(s *Section) {
			s.Interfaces[2] = SectionInterface{Name: "wg-vpn0", Role: "wan", IPv4Method: "dhcp"}
		}, "interfaces[wg-vpn0].name"},
		{"подынтерфейс VLAN картой", func(s *Section) {
			s.Interfaces[0].VLAN = 100
			s.Interfaces[2] = SectionInterface{Name: "enp1s0.100", Role: "lan", IPv4Method: "static", IPv4CIDR: "10.9.9.1/24"}
		}, "interfaces[enp1s0.100].name"},
		{"сервер имён", func(s *Section) { s.Interfaces[0].IPv4DNS = "1.1.1.1]\n    ens9:" }, "interfaces"},
		{"подсети LAN пересекаются", func(s *Section) {
			s.Interfaces[2] = SectionInterface{Name: "enp3s0", Role: "lan", IPv4Method: "static", IPv4CIDR: "192.168.11.5/25"}
		}, "interfaces"},
	} {
		v := goodNetwork()
		c.edit(&v)
		if !ValidateSection(v).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateSection(v).Err())
		}
	}
}

func TestLANs(t *testing.T) {
	got := goodNetwork().LANs()
	if len(got) != 1 || got[0].String() != "192.168.11.1/24" {
		t.Fatalf("подсети LAN: %v", got)
	}
}

func TestSetRole(t *testing.T) {
	v := goodNetwork()
	if err := v.SetRole(RoleInput{Name: "enp1s0", MAC: "02:00:00:00:00:01", Role: "wan", WANMethod: "pppoe",
		CIDR: "1.2.3.4/24", Gateway: "1.2.3.1", DNS: "1.1.1.1", PPPoEUsername: "  office-42 ", VLAN: "100"}); err != nil {
		t.Fatal(err)
	}
	w := v.Interfaces[0]
	if w.IPv4CIDR != "" || w.IPv4Gateway != "" || w.IPv4DNS != "" || w.PPPoEUsername != "office-42" || w.VLAN != 100 || w.WANMetric != 100 {
		t.Fatalf("PPPoE: %+v", w)
	}
	if err := v.SetRole(RoleInput{Name: "enp4s0", MAC: "02:00:00:00:00:04", Role: "lan", CIDR: "10.20.0.1/24", Gateway: "x"}); err != nil {
		t.Fatal(err)
	}
	if n := v.Interfaces[len(v.Interfaces)-1]; n.IPv4Method != "static" || n.IPv4Gateway != "" || n.WANMetric != 100 {
		t.Fatalf("новая LAN: %+v", n)
	}
	if errs := ValidateSection(v); len(errs) > 0 {
		t.Fatalf("раздел после назначений: %v", errs.Err())
	}
	if err := v.SetRole(RoleInput{Name: "enp1s0", Role: "wan", VLAN: "сто"}); err == nil {
		t.Fatal("тег не числом принят")
	}
}

func TestProductIface(t *testing.T) {
	for _, n := range []string{"wg-vpn0", "ovpn-vpn0", "ifb-vpn0", "ifb-vpn1", "ppp0"} {
		if !ProductIface(n) {
			t.Errorf("%s не назван интерфейсом продукта", n)
		}
	}
	if ProductIface("enp1s0") {
		t.Error("карта названа интерфейсом продукта")
	}
}
