package netplangen

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

const (
	RoleWAN = "wan"
	RoleLAN = "lan"
)

const (
	MethodDHCP   = "dhcp"
	MethodStatic = "static"
	MethodPPPoE  = "pppoe"
)

const IfacePPPoE = "ppp0"

func EffectiveWAN(nicName, method string) string {
	if method == MethodPPPoE {
		return IfacePPPoE
	}
	return nicName
}

const MaxVLANID = 4094

func LinkIface(nicName string, vlan int) string {
	if vlan <= 0 || vlan > MaxVLANID {
		return nicName
	}
	if name := fmt.Sprintf("%s.%d", nicName, vlan); len(name) <= 15 {
		return name
	}
	return fmt.Sprintf("vlan%d", vlan)
}

func (p *Plan) EffectiveWANs() []string {
	var names []string
	seen := map[string]bool{}
	for _, i := range p.Interfaces {
		if i.Role != RoleWAN {
			continue
		}
		eff := EffectiveWAN(LinkIface(i.Name, i.VLAN), i.Method)
		if seen[eff] {
			continue
		}
		seen[eff] = true
		names = append(names, eff)
	}
	return names
}

const (
	RendererNetworkd = "networkd"
	RendererNM       = "NetworkManager"
)

var WANNameservers = []string{"9.9.9.9", "149.112.112.112"}

type PlanInterface struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Method string `json:"method"`

	CIDR string `json:"cidr,omitempty"`

	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`

	Username string `json:"username,omitempty"`

	VLAN   int `json:"vlan,omitempty"`
	Metric int `json:"metric,omitempty"`
}

type Plan struct {
	Interfaces []PlanInterface `json:"interfaces"`
	IPv6       bool            `json:"ipv6,omitempty"`
}

var ifnameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

var defIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

var pppoeUserRe = regexp.MustCompile(`^[A-Za-z0-9._@+\-]{1,128}$`)

func ValidPPPoEUsername(s string) bool { return pppoeUserRe.MatchString(s) }

func ValidIfaceName(s string) bool { return ifnameRe.MatchString(s) }

func ValidDefinitionID(id string) bool { return defIDRe.MatchString(id) }

func ParseStatusIDs(statusJSON []byte) map[string]string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(statusJSON, &raw); err != nil {
		return nil
	}
	ids := map[string]string{}
	for name, blob := range raw {
		var entry struct {
			ID string `json:"id"`
		}
		if !ifnameRe.MatchString(name) || json.Unmarshal(blob, &entry) != nil {
			continue
		}
		if entry.ID != "" && ValidDefinitionID(entry.ID) {
			ids[name] = entry.ID
		}
	}
	return ids
}

func (p *Plan) Validate(knownNames map[string]bool) error {
	if len(p.Interfaces) == 0 {
		return fmt.Errorf("план пуст")
	}
	seen := map[string]bool{}
	var lanNets []*net.IPNet
	for _, i := range p.Interfaces {
		if !ifnameRe.MatchString(i.Name) {
			return fmt.Errorf("недопустимое имя интерфейса %q", i.Name)
		}
		if knownNames != nil && !knownNames[i.Name] {
			return fmt.Errorf("интерфейс %q не существует в системе", i.Name)
		}
		if seen[i.Name] {
			return fmt.Errorf("интерфейс %q назначен дважды", i.Name)
		}
		seen[i.Name] = true

		if (i.Gateway != "" || len(i.DNS) > 0) && (i.Role != RoleWAN || i.Method != MethodStatic) {
			return fmt.Errorf("%q: шлюз и серверы имён задаются только у подключения к интернету со статическим адресом", i.Name)
		}

		if i.VLAN != 0 {
			if i.Role != RoleWAN {
				return fmt.Errorf("%q: тег VLAN задаётся только для подключения к интернету", i.Name)
			}
			if i.VLAN < 1 || i.VLAN > MaxVLANID {
				return fmt.Errorf("%q: тег VLAN должен быть от 1 до %d", i.Name, MaxVLANID)
			}

			if link := LinkIface(i.Name, i.VLAN); !ifnameRe.MatchString(link) {
				return fmt.Errorf("%q: с тегом %d получается недопустимое имя %q", i.Name, i.VLAN, link)
			}
		}

		switch i.Role {
		case RoleWAN:
			switch i.Method {
			case MethodDHCP, "":

			case MethodStatic:
				ip, _, err := net.ParseCIDR(i.CIDR)
				if err != nil || ip.To4() == nil {
					return fmt.Errorf("WAN %q: неверный адрес %q (пример: 203.0.113.45/24)", i.Name, i.CIDR)
				}
				if gw := net.ParseIP(i.Gateway); i.Gateway == "" || gw == nil || gw.To4() == nil {
					return fmt.Errorf("WAN %q: неверный шлюз %q (пример: 203.0.113.1)", i.Name, i.Gateway)
				}
				for _, d := range i.DNS {
					if ip := net.ParseIP(d); ip == nil || ip.To4() == nil {
						return fmt.Errorf("WAN %q: неверный сервер имён %q (пример: 1.1.1.1)", i.Name, d)
					}
				}

			case MethodPPPoE:
				if strings.TrimSpace(i.Username) == "" {
					return fmt.Errorf("WAN %q: для PPPoE нужен логин от провайдера", i.Name)
				}

			default:
				return fmt.Errorf("WAN %q: неизвестный метод %q", i.Name, i.Method)
			}
		case RoleLAN:
			if i.Method != MethodStatic {
				return fmt.Errorf("LAN %q: требуется статический адрес", i.Name)
			}
			ip, ipnet, err := net.ParseCIDR(i.CIDR)
			if err != nil || ip.To4() == nil {
				return fmt.Errorf("LAN %q: неверный адрес %q (пример: 192.168.11.1/24)", i.Name, i.CIDR)
			}

			for _, prev := range lanNets {
				if prev.Contains(ip) || ipnet.Contains(prev.IP) {
					return fmt.Errorf("подсети LAN пересекаются: %s и %s", prev, ipnet)
				}
			}
			lanNets = append(lanNets, ipnet)
		default:
			return fmt.Errorf("интерфейс %q: неизвестная роль %q", i.Name, i.Role)
		}
	}
	return nil
}

func (p *Plan) Generate(renderer string, defIDs map[string]string) []byte {
	if renderer != RendererNM {
		renderer = RendererNetworkd
	}
	ifaces := make([]PlanInterface, len(p.Interfaces))
	copy(ifaces, p.Interfaces)
	key := func(i PlanInterface) string {
		if id, ok := defIDs[i.Name]; ok && ValidDefinitionID(id) {
			return id
		}
		return i.Name
	}
	sort.Slice(ifaces, func(a, b int) bool { return key(ifaces[a]) < key(ifaces[b]) })

	var b strings.Builder
	b.WriteString("network:\n")
	b.WriteString("  version: 2\n")
	b.WriteString("  renderer: " + renderer + "\n")
	b.WriteString("  ethernets:\n")
	for _, i := range ifaces {
		b.WriteString("    " + key(i) + ":\n")
		if i.VLAN > 0 {

			renderLinkOnly(&b, i)
			writeIPv6(&b, renderer, false, i.Role)
			continue
		}

		if r, ok := l3Renderers[methodOf(i)]; ok {
			r(&b, i)
		}
		writeIPv6(&b, renderer, p.IPv6, i.Role)
	}
	writeVLANs(&b, renderer, p, ifaces, key)
	return []byte(b.String())
}

func writeVLANs(b *strings.Builder, renderer string, p *Plan, ifaces []PlanInterface,
	key func(PlanInterface) string) {
	var tagged []PlanInterface
	for _, i := range ifaces {
		if i.VLAN > 0 {
			tagged = append(tagged, i)
		}
	}
	if len(tagged) == 0 {
		return
	}
	b.WriteString("  vlans:\n")
	for _, i := range tagged {
		b.WriteString("    " + LinkIface(i.Name, i.VLAN) + ":\n")
		fmt.Fprintf(b, "      id: %d\n", i.VLAN)

		b.WriteString("      link: " + key(i) + "\n")
		if r, ok := l3Renderers[methodOf(i)]; ok {
			r(b, i)
		}
		writeIPv6(b, renderer, p.IPv6, i.Role)
	}
}

type l3Renderer func(b *strings.Builder, i PlanInterface)

var l3Renderers = map[string]l3Renderer{
	MethodDHCP:   renderDHCP,
	MethodStatic: renderStatic,
	MethodPPPoE:  renderPPPoE,
}

func methodOf(i PlanInterface) string {
	if i.Method != "" {
		return i.Method
	}
	if i.Role == RoleLAN {
		return MethodStatic
	}
	return MethodDHCP
}

func renderDHCP(b *strings.Builder, i PlanInterface) {
	metric := i.Metric
	if metric <= 0 {
		metric = 100
	}
	b.WriteString("      dhcp4: true\n")
	fmt.Fprintf(b, "      dhcp4-overrides:\n        use-dns: false\n        route-metric: %d\n", metric)
	b.WriteString("      nameservers:\n        addresses: [" + strings.Join(WANNameservers, ", ") + "]\n")
}

func renderStatic(b *strings.Builder, i PlanInterface) {
	b.WriteString("      dhcp4: false\n")
	b.WriteString("      addresses: [" + i.CIDR + "]\n")
	if i.Gateway == "" {
		return
	}
	metric := i.Metric
	if metric <= 0 {
		metric = 100
	}
	fmt.Fprintf(b, "      routes:\n        - to: default\n          via: %s\n          metric: %d\n", i.Gateway, metric)
	dns := i.DNS
	if len(dns) == 0 {
		dns = WANNameservers
	}
	b.WriteString("      nameservers:\n        addresses: [" + strings.Join(dns, ", ") + "]\n")
}

func renderPPPoE(b *strings.Builder, i PlanInterface) { renderLinkOnly(b, i) }

func renderLinkOnly(b *strings.Builder, _ PlanInterface) {
	b.WriteString("      dhcp4: false\n")
}

func writeIPv6(b *strings.Builder, renderer string, enabled bool, role string) {
	if renderer == RendererNM {
		b.WriteString("      networkmanager:\n        passthrough:\n")
		b.WriteString("          connection.autoconnect-priority: \"" + NMAutoconnectPriority + "\"\n")
		if !enabled {
			b.WriteString("          ipv6.method: disabled\n")
		} else if role == RoleLAN {
			b.WriteString("          ipv6.method: link-local\n")
		}
		return
	}
	if !enabled {
		b.WriteString("      dhcp6: false\n      accept-ra: false\n      link-local: []\n")
		return
	}
	if role == RoleWAN {
		b.WriteString("      dhcp6: true\n      accept-ra: true\n")
	} else {
		b.WriteString("      dhcp6: false\n      accept-ra: false\n")
	}
}

const NMAutoconnectPriority = "100"

func NMConnectionName(definitionID string) string { return "netplan-" + definitionID }

func (p *Plan) DefinitionIDs(defIDs map[string]string) []string {
	out := make([]string, 0, len(p.Interfaces))
	for _, i := range p.Interfaces {
		if id, ok := defIDs[i.Name]; ok && ValidDefinitionID(id) {
			out = append(out, id)
		} else {
			out = append(out, i.Name)
		}

		if i.VLAN > 0 {
			out = append(out, LinkIface(i.Name, i.VLAN))
		}
	}
	sort.Strings(out)
	return out
}
