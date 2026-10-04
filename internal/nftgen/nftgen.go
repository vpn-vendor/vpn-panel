package nftgen

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type FirewallLAN struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type FirewallPlan struct {
	WANs       []string        `json:"wans"`
	LANs       []FirewallLAN   `json:"lans"`
	HiddenMode bool            `json:"hidden_mode,omitempty"`
	IPv6       bool            `json:"ipv6,omitempty"`
	Tunnel     *FirewallTunnel `json:"tunnel,omitempty"`

	Panel *FirewallPanel `json:"panel,omitempty"`
}

type FirewallPanel struct {
	Ports []int `json:"ports"`

	PerSourceConns int `json:"per_source_conns"`

	TotalNewPerSecond int `json:"total_new_per_second"`
}

const (
	PanelNewPerSecond = 10
	PanelNewBurst     = 30

	PanelNewPerCore       = 100
	PanelTotalFloor       = 100
	PanelTotalCeiling     = 1000
	PanelTotalBurstFactor = 2

	panelSetSize = 4096

	panelNewTimeout = "60s"
)

const (
	SetPanelConns = "panel_conns"
	SetPanelNew   = "panel_new"
)

func (p *FirewallPanel) validate() error {
	if len(p.Ports) == 0 {
		return fmt.Errorf("пределы панели: не указан ни один порт")
	}
	seen := map[int]bool{}
	for _, port := range p.Ports {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("пределы панели: недопустимый порт %d", port)
		}
		if seen[port] {
			return fmt.Errorf("пределы панели: порт %d указан дважды", port)
		}
		seen[port] = true
	}
	if p.PerSourceConns <= 0 {
		return fmt.Errorf("пределы панели: предел соединений с адреса должен быть больше нуля")
	}
	if p.TotalNewPerSecond <= 0 {
		return fmt.Errorf("пределы панели: совокупный предел новых соединений должен быть больше нуля")
	}
	return nil
}

func PanelTotalNewPerSecond(cores int) int {
	total := PanelNewPerCore * cores
	if total < PanelTotalFloor {
		return PanelTotalFloor
	}
	if total > PanelTotalCeiling {
		return PanelTotalCeiling
	}
	return total
}

func (p *FirewallPanel) portSet() string {
	nums := append([]int(nil), p.Ports...)
	sort.Ints(nums)
	ports := make([]string, 0, len(nums))
	for _, port := range nums {
		ports = append(ports, strconv.Itoa(port))
	}
	return "{ " + strings.Join(ports, ", ") + " }"
}

type FirewallTunnel struct {
	Iface        string `json:"iface"`
	Endpoint     string `json:"endpoint,omitempty"`
	EndpointPort int    `json:"endpoint_port,omitempty"`

	EndpointProto string `json:"endpoint_proto,omitempty"`
	Mark          int    `json:"mark,omitempty"`

	Address string `json:"address,omitempty"`
}

func (p *FirewallPlan) Black() bool { return p.Tunnel != nil && p.Tunnel.Iface != "" }

var nftNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

func (p *FirewallPlan) Validate(knownNames map[string]bool) error {
	if len(p.WANs) == 0 || len(p.LANs) == 0 {
		return fmt.Errorf("для раздачи интернета нужны и WAN, и LAN")
	}
	seen := map[string]bool{}
	check := func(name string) error {
		if !nftNameRe.MatchString(name) {
			return fmt.Errorf("недопустимое имя интерфейса %q", name)
		}
		if knownNames != nil && !knownNames[name] {
			return fmt.Errorf("интерфейс %q не существует в системе", name)
		}
		if seen[name] {
			return fmt.Errorf("интерфейс %q указан дважды", name)
		}
		seen[name] = true
		return nil
	}
	for _, w := range p.WANs {
		if err := check(w); err != nil {
			return err
		}
	}
	for _, l := range p.LANs {
		if err := check(l.Name); err != nil {
			return err
		}
		if ip, _, err := net.ParseCIDR(l.CIDR); err != nil || ip.To4() == nil {
			return fmt.Errorf("LAN %q: неверный адрес %q", l.Name, l.CIDR)
		}
	}

	if p.Black() && !nftNameRe.MatchString(p.Tunnel.Iface) {
		return fmt.Errorf("недопустимое имя защищённого канала %q", p.Tunnel.Iface)
	}
	if p.Black() {
		if err := p.Tunnel.validateOutput(); err != nil {
			return err
		}
	}
	if p.Panel != nil {
		if err := p.Panel.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (t *FirewallTunnel) validateOutput() error {
	if t.Address != "" {
		if ip := net.ParseIP(t.Address); ip == nil || ip.To4() == nil {
			return fmt.Errorf("неверный адрес шлюза в канале %q", t.Address)
		}
	}
	if t.Endpoint == "" {
		return nil
	}
	if ip := net.ParseIP(t.Endpoint); ip == nil || ip.To4() == nil {
		return fmt.Errorf("неверный адрес сервера подключения %q", t.Endpoint)
	}
	if t.EndpointPort < 1 || t.EndpointPort > 65535 {
		return fmt.Errorf("неверный порт сервера подключения %d", t.EndpointPort)
	}
	switch t.EndpointProto {
	case "", "udp", "tcp":
	default:
		return fmt.Errorf("неверный транспорт сервера подключения %q", t.EndpointProto)
	}
	if t.Mark < 0 || t.Mark > 0xffffffff {
		return fmt.Errorf("неверная служебная метка канала %d", t.Mark)
	}
	return nil
}

func quotedSet(names []string) string {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	quoted := make([]string, len(sorted))
	for i, n := range sorted {
		quoted[i] = `"` + n + `"`
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

const pingLimit = "limit rate 5/second burst 10 packets"

const (
	SetForeignDNS = "diag_foreign_dns"
	SetIPv6Tunnel = "diag_ipv6_tunnel"
	SetOwnVPN     = "diag_own_vpn"
	SetUpdatesP2P = "diag_updates_p2p"
)

var DiagSets = []string{SetForeignDNS, SetIPv6Tunnel, SetOwnVPN, SetUpdatesP2P}

const (
	diagSetSize       = 4096
	DiagSetTimeoutSec = 86400
	diagSetTimeout    = "1d"
)

const icmpv6Required = "{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, " +
	"nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, " +
	"mld-listener-query, mld-listener-report, mld-listener-reduction }"

func exitNames(p *FirewallPlan) []string {
	if p.Black() {
		return []string{p.Tunnel.Iface}
	}
	return p.WANs
}

func (p *FirewallPlan) Generate() []byte {
	wanSet := quotedSet(p.WANs)
	lanNames := make([]string, 0, len(p.LANs))
	for _, l := range p.LANs {
		lanNames = append(lanNames, l.Name)
	}
	lanSet := quotedSet(lanNames)

	outNames := append([]string(nil), p.WANs...)
	if p.Black() {
		outNames = append(outNames, p.Tunnel.Iface)
	}
	outSet := quotedSet(outNames)

	lanIPs := make([]string, 0, len(p.LANs))
	for _, l := range p.LANs {
		if ip, _, err := net.ParseCIDR(l.CIDR); err == nil {
			lanIPs = append(lanIPs, ip.String())
		}
	}
	sort.Strings(lanIPs)

	var b strings.Builder
	b.WriteString("table inet vpn_panel\n")
	b.WriteString("delete table inet vpn_panel\n")
	b.WriteString("table inet vpn_panel {\n")
	for _, name := range DiagSets {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n\t\tcounter\n\t}\n", name, diagSetSize, diagSetTimeout)
	}
	if p.Panel != nil {

		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic\n\t}\n", SetPanelConns, panelSetSize)
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n\t}\n", SetPanelNew, panelSetSize, panelNewTimeout)
	}
	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")

	fmt.Fprintf(&b, "\t\toifname %s masquerade\n", outSet)
	b.WriteString("\t}\n")

	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy drop;\n")
	b.WriteString("\t\tiif \"lo\" accept\n")

	if p.Black() {
		fmt.Fprintf(&b, "\t\tiifname \"%s\" icmp type echo-reply counter comment \"%s\"\n", p.Tunnel.Iface, EchoInComment)
	}

	if !p.HiddenMode {
		fmt.Fprintf(&b, "\t\tiifname %s icmp type echo-request %s accept\n", wanSet, pingLimit)
	}
	fmt.Fprintf(&b, "\t\tiifname %s icmp type echo-request drop\n", wanSet)
	if p.IPv6 {
		if !p.HiddenMode {
			fmt.Fprintf(&b, "\t\tiifname %s icmpv6 type echo-request %s accept\n", wanSet, pingLimit)
		}
		fmt.Fprintf(&b, "\t\tiifname %s icmpv6 type echo-request drop\n", wanSet)
	}
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")

	if p.Panel != nil {
		ports := p.Panel.portSet()
		fmt.Fprintf(&b, "\t\tiifname %s tcp dport %s ct state new add @%s { ip saddr ct count over %d } counter drop\n",
			lanSet, ports, SetPanelConns, p.Panel.PerSourceConns)
		fmt.Fprintf(&b, "\t\tiifname %s tcp dport %s ct state new add @%s { ip saddr limit rate over %d/second burst %d packets } counter drop\n",
			lanSet, ports, SetPanelNew, PanelNewPerSecond, PanelNewBurst)
		fmt.Fprintf(&b, "\t\tiifname %s tcp dport %s ct state new limit rate over %d/second burst %d packets counter drop\n",
			lanSet, ports, p.Panel.TotalNewPerSecond, p.Panel.TotalNewPerSecond*PanelTotalBurstFactor)
	}

	fmt.Fprintf(&b, "\t\tiifname %s accept\n", lanSet)

	fmt.Fprintf(&b, "\t\tiifname %s udp sport 67 udp dport 68 accept\n", wanSet)

	fmt.Fprintf(&b, "\t\tiifname %s icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n", wanSet)
	if p.IPv6 {
		fmt.Fprintf(&b, "\t\tiifname %s udp sport 547 udp dport 546 accept\n", wanSet)
		fmt.Fprintf(&b, "\t\tiifname %s icmpv6 type %s accept\n", wanSet, icmpv6Required)
	} else {

		b.WriteString("\t\tmeta nfproto ipv6 drop\n")
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain forward {\n")

	b.WriteString("\t\ttype filter hook forward priority filter; policy drop;\n")

	b.WriteString("\t\ttcp flags syn tcp option maxseg size set rt mtu\n")

	fmt.Fprintf(&b, "\t\tct state established,related oifname %s accept\n", quotedSet(append(append([]string(nil), lanNames...), exitNames(p)...)))

	fmt.Fprintf(&b, "\t\tiifname %s meta l4proto { tcp, udp } th dport 53 ip daddr != { %s } update @%s { ip saddr }\n", lanSet, strings.Join(lanIPs, ", "), SetForeignDNS)
	fmt.Fprintf(&b, "\t\tiifname %s oifname %s udp dport { 500, 1194, 4500, 51820 } update @%s { ip saddr }\n", lanSet, outSet, SetOwnVPN)
	fmt.Fprintf(&b, "\t\tiifname %s oifname %s tcp dport 1194 update @%s { ip saddr }\n", lanSet, outSet, SetOwnVPN)
	fmt.Fprintf(&b, "\t\tiifname %s oifname %s tcp dport 7680 update @%s { ip saddr }\n", lanSet, outSet, SetUpdatesP2P)

	fmt.Fprintf(&b, "\t\tiifname %s udp dport 3544 update @%s { ip saddr } drop\n", lanSet, SetIPv6Tunnel)
	fmt.Fprintf(&b, "\t\tiifname %s meta l4proto 41 update @%s { ip saddr } drop\n", lanSet, SetIPv6Tunnel)

	b.WriteString("\t\tmeta nfproto ipv6 drop\n")
	if p.Black() {

		fmt.Fprintf(&b, "\t\tiifname %s oifname \"%s\" accept\n", lanSet, p.Tunnel.Iface)
	} else {
		fmt.Fprintf(&b, "\t\tiifname %s oifname %s accept\n", lanSet, wanSet)
	}
	b.WriteString("\t}\n")
	p.writeOutputChain(&b)
	p.writeLeakWatch(&b)
	p.writeMarkKeep(&b)
	p.writeTunnelGuard(&b)
	b.WriteString("}\n")
	return []byte(b.String())
}

func (p *FirewallPlan) egressAllowed() []string {
	t := p.Tunnel
	proto := t.EndpointProto
	if proto == "" {
		proto = "udp"
	}
	out := []string{
		"ct state established,related ct direction reply",
		fmt.Sprintf("ip daddr %s %s dport %d", t.Endpoint, proto, t.EndpointPort),
	}
	if t.Mark > 0 {
		out = append(out, fmt.Sprintf("meta mark 0x%x", t.Mark))
	}
	return append(out, "udp sport 68 udp dport 67")
}

func (p *FirewallPlan) writeLeakWatch(b *strings.Builder) {
	if !p.Black() || p.Tunnel.Endpoint == "" {
		return
	}
	b.WriteString("\tchain leak_watch {\n")
	b.WriteString("\t\ttype filter hook postrouting priority srcnat + 10; policy accept;\n")
	fmt.Fprintf(b, "\t\toifname != %s return\n", quotedSet(p.WANs))
	for _, m := range p.egressAllowed() {
		fmt.Fprintf(b, "\t\t%s return\n", m)
	}
	fmt.Fprintf(b, "\t\tcounter comment \"%s\"\n", LeakWatchComment)
	b.WriteString("\t}\n")
}

func (p *FirewallPlan) writeMarkKeep(b *strings.Builder) {
	if !p.Black() || p.Tunnel.Mark <= 0 {
		return
	}
	m := p.Tunnel.Mark
	b.WriteString("\tchain mark_save {\n")
	b.WriteString("\t\ttype filter hook postrouting priority mangle; policy accept;\n")
	fmt.Fprintf(b, "\t\tmeta mark 0x%x ct mark set meta mark\n", m)
	b.WriteString("\t}\n")
	b.WriteString("\tchain mark_restore {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	fmt.Fprintf(b, "\t\tct mark 0x%x meta mark set ct mark\n", m)
	b.WriteString("\t}\n")
}

func (p *FirewallPlan) writeTunnelGuard(b *strings.Builder) {
	if !p.Black() || p.Tunnel.Address == "" {
		return
	}
	b.WriteString("\tchain tunnel_guard {\n")
	b.WriteString("\t\ttype filter hook prerouting priority raw; policy accept;\n")
	fmt.Fprintf(b, "\t\tiifname != \"%s\" ip daddr %s fib saddr type != local counter drop comment \"%s\"\n",
		p.Tunnel.Iface, p.Tunnel.Address, TunnelGuardComment)
	b.WriteString("\t}\n")
}

const TunnelGuardComment = "адрес канала не через канал"

const (
	EchoOutComment = "эхо шлюза в канал"
	EchoInComment  = "ответ эха из канала"
)

const LeakWatchComment = "утечка мимо канала"

const LeakDropComment = "выход мимо канала"

func (p *FirewallPlan) writeOutputChain(b *strings.Builder) {
	if !p.Black() || p.Tunnel.Endpoint == "" {
		return
	}
	t := p.Tunnel
	free := []string{"lo", t.Iface}
	for _, l := range p.LANs {
		free = append(free, l.Name)
	}
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy accept;\n")
	fmt.Fprintf(b, "\t\toifname \"%s\" icmp type echo-request counter comment \"%s\"\n", t.Iface, EchoOutComment)
	fmt.Fprintf(b, "\t\toifname %s accept\n", quotedSet(free))
	for _, m := range p.egressAllowed() {
		fmt.Fprintf(b, "\t\t%s accept\n", m)
	}

	fmt.Fprintf(b, "\t\tmeta nfproto ipv6 counter drop comment \"%s\"\n", LeakDropComment)
	fmt.Fprintf(b, "\t\tcounter drop comment \"%s\"\n", LeakDropComment)
	b.WriteString("\t}\n")
}
