package vpn

import "testing"

func goodVPN() Section {
	return Section{ActiveSlug: "office", Mode: "black", OnFailure: "strict", MTU: 0, DNSChoice: "ours",
		Profiles: []SectionProfile{
			{Name: "Офис #1", Slug: "office", Protocol: "wireguard", Transport: "udp", EndpointHost: "vpn.example.net",
				EndpointPort: 51820, PeerKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", Addresses: "10.66.66.2/32",
				AllowedIPs: "0.0.0.0/0, ::/0", ConfigDNS: "10.66.66.1", ConfigMTU: 1420, Keepalive: 25, FullTunnel: true,
				ProbeTarget: "10.66.66.1"},
			{Name: "Резерв", Slug: "reserve", Protocol: "openvpn", Transport: "tcp", EndpointHost: "198.51.100.7",
				EndpointPort: 443, Keepalive: 10, FullTunnel: true},
		}}
}

func TestValidateSection(t *testing.T) {
	if errs := ValidateSection(goodVPN()); len(errs) > 0 {
		t.Fatalf("годный раздел отвергнут: %v", errs.Err())
	}
	for _, c := range []struct {
		name string
		edit func(*Section)
		path string
	}{
		{"режим", func(s *Section) { s.Mode = "grey" }, "mode"},
		{"при падении", func(s *Section) { s.OnFailure = "pray" }, "on_failure"},
		{"серверы имён", func(s *Section) { s.DNSChoice = "google" }, "dns_choice"},
		{"MTU", func(s *Section) { s.MTU = 9000 }, "mtu"},
		{"выбран несуществующий", func(s *Section) { s.ActiveSlug = "ghost" }, "active_slug"},
		{"защищённый без профиля", func(s *Section) { s.ActiveSlug = "" }, "active_slug"},
		{"имя профиля повторяется", func(s *Section) { s.Profiles[1].Slug = "office" }, "profiles[office].slug"},
		{"название с переводом строки", func(s *Section) { s.Profiles[0].Name = "Офис\nx" }, "profiles[office].name"},
		{"пустое название", func(s *Section) { s.Profiles[0].Name = "  " }, "profiles[office].name"},
		{"имя файла", func(s *Section) { s.Profiles[0].Slug = "../etc" }, "profiles[0].slug"},
		{"протокол", func(s *Section) { s.Profiles[0].Protocol = "ipsec" }, "profiles[office].protocol"},
		{"WireGuard поверх tcp", func(s *Section) { s.Profiles[0].Transport = "tcp" }, "profiles[office].transport"},
		{"адрес сервера", func(s *Section) { s.Profiles[0].EndpointHost = "vpn example" }, "profiles[office].endpoint_host"},
		{"порт", func(s *Section) { s.Profiles[0].EndpointPort = 70000 }, "profiles[office].endpoint_port"},
		{"ключ сервера", func(s *Section) { s.Profiles[0].PeerKey = "abc" }, "profiles[office].peer_key"},
		{"адреса канала", func(s *Section) { s.Profiles[0].Addresses = "10.66.66.2" }, "profiles[office].addresses"},
		{"сети канала", func(s *Section) { s.Profiles[0].AllowedIPs = "0.0.0.0/0,,::/0" }, "profiles[office].allowed_ips"},
		{"ключ у OpenVPN", func(s *Section) { s.Profiles[1].PeerKey = "x" }, "profiles[reserve].peer_key"},
		{"DNS из файла", func(s *Section) { s.Profiles[0].ConfigDNS = "10.66.66.1; rm" }, "profiles[office].config_dns"},
		{"MTU из файла", func(s *Section) { s.Profiles[0].ConfigMTU = 100 }, "profiles[office].config_mtu"},
		{"интервал связи", func(s *Section) { s.Profiles[0].Keepalive = -1 }, "profiles[office].keepalive"},
		{"цель пробы", func(s *Section) { s.Profiles[0].ProbeTarget = "10.66.66.1.1" }, "profiles[office].probe_target"},
		{"цель пробы не в каноне", func(s *Section) { s.Profiles[0].ProbeTarget = "::ffff:10.66.66.1" }, "profiles[office].probe_target"},
	} {
		v := goodVPN()
		c.edit(&v)
		if !ValidateSection(v).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateSection(v).Err())
		}
	}
}
