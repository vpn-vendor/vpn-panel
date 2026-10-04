package unboundgen

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

const LocalDomain = "vpn.lan"

var ShortNames = []string{"pc", "vpn"}

var Upstream = []string{"9.9.9.9", "149.112.112.112"}

type Segment struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type Plan struct {
	Segments        []Segment `json:"segments"`
	OutgoingAddress string    `json:"outgoing_address,omitempty"`
	Forwarders      []string  `json:"forwarders,omitempty"`
}

func (p *Plan) forwarders() []string {
	if len(p.Forwarders) == 0 {
		return Upstream
	}
	return p.Forwarders
}

var ifnameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

func (p *Plan) Validate(knownNames map[string]bool) error {
	if len(p.Segments) == 0 {
		return fmt.Errorf("нет сегментов локальной сети")
	}
	seen := map[string]bool{}
	for _, s := range p.Segments {
		if !ifnameRe.MatchString(s.Name) {
			return fmt.Errorf("недопустимое имя интерфейса %q", s.Name)
		}
		if knownNames != nil && !knownNames[s.Name] {
			return fmt.Errorf("интерфейс %q не существует в системе", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("интерфейс %q указан дважды", s.Name)
		}
		seen[s.Name] = true
		ip, _, err := net.ParseCIDR(s.CIDR)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("сегмент %q: неверный адрес %q", s.Name, s.CIDR)
		}
		if ip.IsUnspecified() {

			return fmt.Errorf("сегмент %q: адрес 0.0.0.0 запрещён", s.Name)
		}
	}
	if p.OutgoingAddress != "" {
		ip := net.ParseIP(p.OutgoingAddress)
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
			return fmt.Errorf("неверный адрес защищённого канала %q", p.OutgoingAddress)
		}
	}
	for _, f := range p.Forwarders {
		if ip := net.ParseIP(f); ip == nil || ip.IsUnspecified() {
			return fmt.Errorf("неверный адрес вышестоящего сервера имён %q", f)
		}
	}
	return nil
}

func (p *Plan) ListenAddresses() []string {
	addrs := []string{"127.0.0.1"}
	for _, s := range p.sortedSegments() {
		if ip, _, err := net.ParseCIDR(s.CIDR); err == nil {
			addrs = append(addrs, ip.String())
		}
	}
	return addrs
}

func (p *Plan) sortedSegments() []Segment {
	out := make([]Segment, len(p.Segments))
	copy(out, p.Segments)
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

func (p *Plan) Generate() []byte {
	segments := p.sortedSegments()

	var b strings.Builder
	b.WriteString("server:\n")

	for _, addr := range p.ListenAddresses() {
		b.WriteString("    interface: " + addr + "\n")
	}

	b.WriteString("    access-control: 0.0.0.0/0 refuse\n")
	b.WriteString("    access-control: 127.0.0.0/8 allow\n")
	for _, s := range segments {
		if _, ipnet, err := net.ParseCIDR(s.CIDR); err == nil {
			b.WriteString("    access-control: " + ipnet.String() + " allow\n")
		}
	}

	b.WriteString("    ip-freebind: yes\n")

	if p.OutgoingAddress != "" {
		b.WriteString("    outgoing-interface: " + p.OutgoingAddress + "\n")
		b.WriteString("    do-ip6: no\n")
	}
	b.WriteString("    hide-identity: yes\n")
	b.WriteString("    hide-version: yes\n")

	b.WriteString("    prefetch: yes\n")
	b.WriteString("    cache-min-ttl: 60\n")
	b.WriteString("    cache-max-ttl: 86400\n")

	b.WriteString("    infra-keep-probing: yes\n")

	b.WriteString("    local-zone: \"" + LocalDomain + ".\" static\n")
	for _, s := range segments {
		if ip, _, err := net.ParseCIDR(s.CIDR); err == nil {
			b.WriteString("    local-data: \"" + LocalDomain + ". IN A " + ip.String() + "\"\n")
			b.WriteString("    local-data-ptr: \"" + ip.String() + " " + LocalDomain + "\"\n")
			for _, short := range ShortNames {
				b.WriteString("    local-data: \"" + short + "." + LocalDomain + ". IN A " + ip.String() + "\"\n")
			}
		}
	}

	for _, short := range ShortNames {
		b.WriteString("    local-zone: \"" + short + ".\" static\n")
		for _, s := range segments {
			if ip, _, err := net.ParseCIDR(s.CIDR); err == nil {
				b.WriteString("    local-data: \"" + short + ". IN A " + ip.String() + "\"\n")
			}
		}
	}

	b.WriteString("\nforward-zone:\n")
	b.WriteString("    name: \".\"\n")
	for _, addr := range p.forwarders() {
		b.WriteString("    forward-addr: " + addr + "\n")
	}
	return []byte(b.String())
}
