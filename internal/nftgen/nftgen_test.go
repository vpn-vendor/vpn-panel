package nftgen

import (
	"strings"
	"testing"
)

func known() map[string]bool {
	return map[string]bool{"ens3": true, "ens4": true, "enp5s0": true}
}

func TestGenerateSingleWANLAN(t *testing.T) {
	p := FirewallPlan{
		WANs: []string{"ens3"},
		LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}},
	}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate())
	want := `table inet vpn_panel
delete table inet vpn_panel
table inet vpn_panel {
	set diag_foreign_dns {
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1d
		counter
	}
	set diag_ipv6_tunnel {
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1d
		counter
	}
	set diag_own_vpn {
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1d
		counter
	}
	set diag_updates_p2p {
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1d
		counter
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "ens3" } masquerade
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		iifname { "ens3" } icmp type echo-request limit rate 5/second burst 10 packets accept
		iifname { "ens3" } icmp type echo-request drop
		ct state established,related accept
		ct state invalid drop
		iifname { "ens4" } accept
		iifname { "ens3" } udp sport 67 udp dport 68 accept
		iifname { "ens3" } icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
		meta nfproto ipv6 drop
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		tcp flags syn tcp option maxseg size set rt mtu
		ct state established,related oifname { "ens3", "ens4" } accept
		iifname { "ens4" } meta l4proto { tcp, udp } th dport 53 ip daddr != { 192.168.77.1 } update @diag_foreign_dns { ip saddr }
		iifname { "ens4" } oifname { "ens3" } udp dport { 500, 1194, 4500, 51820 } update @diag_own_vpn { ip saddr }
		iifname { "ens4" } oifname { "ens3" } tcp dport 1194 update @diag_own_vpn { ip saddr }
		iifname { "ens4" } oifname { "ens3" } tcp dport 7680 update @diag_updates_p2p { ip saddr }
		iifname { "ens4" } udp dport 3544 update @diag_ipv6_tunnel { ip saddr } drop
		iifname { "ens4" } meta l4proto 41 update @diag_ipv6_tunnel { ip saddr } drop
		meta nfproto ipv6 drop
		iifname { "ens4" } oifname { "ens3" } accept
	}
}
`
	if out != want {
		t.Fatalf("ruleset mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

func TestHiddenModeDropsEcho(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}, HiddenMode: true}
	out := string(p.Generate())
	if strings.Contains(out, "echo-request limit") || !strings.Contains(out, `iifname { "ens3" } icmp type echo-request drop`) {
		t.Fatalf("в скрытом режиме echo только drop:\n%s", out)
	}
	if !strings.Contains(out, "icmp type { destination-unreachable, time-exceeded, parameter-problem } accept") {
		t.Fatal("ICMP-ошибки к шлюзу обязаны проходить и в скрытом режиме (PMTUD)")
	}
}

func TestIPv6EnabledKeepsRFC4890Minimum(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}, IPv6: true}
	out := string(p.Generate())
	for _, want := range []string{
		`iifname { "ens3" } udp sport 547 udp dport 546 accept`,
		"icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-reduction } accept",
		`iifname { "ens3" } icmpv6 type echo-request limit rate 5/second burst 10 packets accept`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет правила %q:\n%s", want, out)
		}
	}

	input := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	if strings.Contains(input, "meta nfproto ipv6 drop") {
		t.Fatal("при включённом IPv6 вход не должен глушить v6 целиком")
	}
	forward := out[strings.Index(out, "chain forward"):]
	if !strings.Contains(forward, "meta nfproto ipv6 drop") {
		t.Fatal("форвард IPv6 обязан оставаться закрытым")
	}

	p.HiddenMode = true
	hidden := string(p.Generate())
	if strings.Contains(hidden, "echo-request limit") || !strings.Contains(hidden, "nd-router-advert") {
		t.Fatalf("скрытый режим + IPv6: echo нет, ND есть:\n%s", hidden)
	}
}

func TestGenerateMultiWANLANDeterministic(t *testing.T) {
	a := FirewallPlan{
		WANs: []string{"enp5s0", "ens3"},
		LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}},
	}
	b := FirewallPlan{
		WANs: []string{"ens3", "enp5s0"},
		LANs: a.LANs,
	}
	if string(a.Generate()) != string(b.Generate()) {
		t.Fatal("output must not depend on input order")
	}
	if !strings.Contains(string(a.Generate()), `oifname { "enp5s0", "ens3" } masquerade`) {
		t.Fatalf("want sorted wan set, got:\n%s", a.Generate())
	}
}

func TestRuleOrderEstablishedBeforeDrops(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}
	out := string(p.Generate())
	input := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	echo := strings.Index(input, "icmp type echo-request limit")
	echoDrop := strings.Index(input, "icmp type echo-request drop")
	est := strings.Index(input, "ct state established,related accept")
	inv := strings.Index(input, "ct state invalid drop")
	v6 := strings.Index(input, "meta nfproto ipv6 drop")

	if echo >= echoDrop || echoDrop >= est || est >= inv || inv >= v6 {
		t.Fatalf("порядок правил входа нарушен:\n%s", input)
	}
	if strings.Contains(out, "reject") {
		t.Fatal("reject на WAN не используется никогда")
	}
}

func TestDiagSetsAreBoundedAndCountOnly(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}
	out := string(p.Generate())
	for _, name := range DiagSets {
		if !strings.Contains(out, "set "+name+" {\n\t\ttype ipv4_addr\n\t\tsize 4096\n\t\tflags dynamic,timeout\n\t\ttimeout 1d\n\t\tcounter") {
			t.Fatalf("набор %s без потолка/таймаута/счётчика:\n%s", name, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "update @diag_") && !strings.Contains(line, "diag_ipv6_tunnel") {
			if strings.Contains(line, "accept") || strings.Contains(line, "drop") || strings.Contains(line, "reject") {
				t.Fatalf("правило учёта не должно менять вердикт: %s", line)
			}
		}
	}
	if !strings.Contains(out, "ip daddr != { 10.0.0.1 }") {
		t.Fatal("запросы к резолверу шлюза не считаются чужим DNS")
	}
}

func TestGenerateBlackMode(t *testing.T) {
	p := FirewallPlan{
		WANs:   []string{"ens3"},
		LANs:   []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}},
		Tunnel: &FirewallTunnel{Iface: "wg-vpn0"},
	}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate())
	forward := out[strings.Index(out, "chain forward"):]

	if !strings.Contains(forward, `iifname { "ens4" } oifname "wg-vpn0" accept`) {
		t.Fatalf("нет выхода офиса в защищённый канал:\n%s", forward)
	}

	if strings.Contains(forward, `iifname { "ens4" } oifname { "ens3" } accept`) {
		t.Fatalf("в чёрном режиме офис не имеет права выходить мимо канала:\n%s", forward)
	}
	if !strings.Contains(out, `oifname { "ens3", "wg-vpn0" } masquerade`) {
		t.Fatalf("нет подмены адреса на выходе в канал:\n%s", out)
	}

	if !strings.Contains(forward, `oifname { "ens3", "wg-vpn0" } udp dport { 500, 1194, 4500, 51820 } update @diag_own_vpn`) {
		t.Fatalf("паспорта устройств перестали видеть чужой VPN в чёрном режиме:\n%s", forward)
	}

	input := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	for _, ln := range strings.Split(input, "\n") {
		if strings.Contains(ln, "wg-vpn0") && (strings.Contains(ln, "accept") || strings.Contains(ln, "drop")) {
			t.Fatalf("канал не имеет права открывать вход на шлюз: %q", ln)
		}
	}
}

func TestEchoCountersBlackModeOnly(t *testing.T) {
	black := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}},
		Tunnel: &FirewallTunnel{Iface: "ovpn-vpn0", Endpoint: "192.0.2.10", EndpointPort: 1194, EndpointProto: "udp", Mark: 51820}}
	if err := black.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(black.Generate())
	in := `iifname "ovpn-vpn0" icmp type echo-reply counter comment "` + EchoInComment + `"`
	outRule := `oifname "ovpn-vpn0" icmp type echo-request counter comment "` + EchoOutComment + `"`
	input := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	if i, e := strings.Index(input, in), strings.Index(input, "ct state established,related accept"); i < 0 || e < 0 || i > e {
		t.Fatalf("счёт ответов эха отсутствует или стоит после established:\n%s", input)
	}
	output := out[strings.Index(out, "chain output"):]
	if i, a := strings.Index(output, outRule), strings.Index(output, `} accept`); i < 0 || a < 0 || i > a {
		t.Fatalf("счёт эха в канал отсутствует или стоит после разрешения:\n%s", output)
	}
	white := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}}}
	if w := string(white.Generate()); strings.Contains(w, EchoInComment) || strings.Contains(w, EchoOutComment) {
		t.Fatalf("в прямом режиме канала нет — и счёта эха тоже:\n%s", w)
	}
}

func TestModeSwitchIsFullRegeneration(t *testing.T) {
	white := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}
	black := white
	black.Tunnel = &FirewallTunnel{Iface: "wg-vpn0"}
	backToWhite := black
	backToWhite.Tunnel = nil

	if string(white.Generate()) != string(backToWhite.Generate()) {
		t.Fatal("возврат в белый режим обязан давать ровно исходный рулсет")
	}
	if string(white.Generate()) == string(black.Generate()) {
		t.Fatal("режимы обязаны различаться рулсетом, а не настройкой поверх него")
	}
	if strings.Contains(string(backToWhite.Generate()), "wg-vpn0") {
		t.Fatal("в белом рулсете не должно остаться следов канала")
	}
}

func TestMSSClampAlwaysFirstInForward(t *testing.T) {
	for _, p := range []FirewallPlan{
		{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}},
		{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}, Tunnel: &FirewallTunnel{Iface: "wg-vpn0"}},
	} {
		out := string(p.Generate())
		forward := out[strings.Index(out, "chain forward"):]
		clamp := strings.Index(forward, "tcp flags syn tcp option maxseg size set rt mtu")
		est := strings.Index(forward, "ct state established,related")
		if clamp < 0 || est < 0 {
			t.Fatalf("подгонка размера сегмента обязана быть всегда:\n%s", forward)
		}
		if clamp > est {
			t.Fatalf("подгонка обязана стоять до established:\n%s", forward)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		plan FirewallPlan
	}{
		{"no wan", FirewallPlan{LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}},
		{"no lan", FirewallPlan{WANs: []string{"ens3"}}},
		{"unknown nic", FirewallPlan{WANs: []string{"eth9"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}},
		{"bad name", FirewallPlan{WANs: []string{"a;b"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}},
		{"dup", FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens3", CIDR: "10.0.0.1/24"}}}},
		{"bad cidr", FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "nope"}}}},
		{"bad tunnel name", FirewallPlan{WANs: []string{"ens3"},
			LANs:   []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}},
			Tunnel: &FirewallTunnel{Iface: "wg vpn0; nft flush ruleset"}}},
		{"bad endpoint proto", FirewallPlan{WANs: []string{"ens3"},
			LANs:   []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}},
			Tunnel: &FirewallTunnel{Iface: "ovpn-vpn0", Endpoint: "203.0.113.5", EndpointPort: 1194, EndpointProto: "icmp; nft flush ruleset"}}},
	}
	for _, c := range cases {
		if err := c.plan.Validate(known()); err == nil {
			t.Fatalf("%s: want error", c.name)
		}
	}
}

func TestOutputChainFollowsTransport(t *testing.T) {
	base := func(proto string) FirewallPlan {
		return FirewallPlan{
			WANs: []string{"ens3"},
			LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}},
			Tunnel: &FirewallTunnel{Iface: "ovpn-vpn0", Endpoint: "203.0.113.5",
				EndpointPort: 1194, EndpointProto: proto, Mark: 51820},
		}
	}
	for _, c := range []struct{ proto, want, deny string }{
		{"", "ip daddr 203.0.113.5 udp dport 1194 accept", "tcp dport 1194"},
		{"udp", "ip daddr 203.0.113.5 udp dport 1194 accept", "tcp dport 1194"},
		{"tcp", "ip daddr 203.0.113.5 tcp dport 1194 accept", "udp dport 1194"},
	} {
		p := base(c.proto)
		if err := p.Validate(known()); err != nil {
			t.Fatalf("%q: validate: %v", c.proto, err)
		}
		out := string(p.Generate())
		output := out[strings.Index(out, "chain output"):]
		if !strings.Contains(output, c.want) {
			t.Fatalf("%q: нет правила %q:\n%s", c.proto, c.want, output)
		}
		if strings.Contains(output, c.deny) {
			t.Fatalf("%q: открыт лишний транспорт %q:\n%s", c.proto, c.deny, output)
		}
		if !strings.Contains(output, "meta mark 0xca6c accept") {
			t.Fatalf("%q: нет правила по служебной метке:\n%s", c.proto, output)
		}
	}
}
