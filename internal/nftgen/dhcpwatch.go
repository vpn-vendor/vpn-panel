package nftgen

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DHCPWatchTable = "vpn_panel_dhcp" //nolint:gosec

const (
	DHCPSeenSet = "dhcp_seen"

	DHCPWindowSet  = "dhcp_window"
	DHCPWatchChain = "watch"
)

const (
	DHCPFresh  = 4 * 24 * time.Hour
	DHCPWindow = 24 * time.Hour
)

const dhcpServerPort = 67

const dhcpWatchPriority = "raw - 10"

type DHCPWatch struct {
	LANs     []string `json:"lans"`
	Prefixes []string `json:"prefixes"`

	OwnMACs []string `json:"own_macs,omitempty"`
}

var macRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

func (w DHCPWatch) Validate() error {
	if len(w.LANs) == 0 {
		return fmt.Errorf("наблюдение DHCP: нет карт локальной сети")
	}
	seen := map[string]bool{}
	for _, name := range w.LANs {
		if !nftNameRe.MatchString(name) {
			return fmt.Errorf("наблюдение DHCP: недопустимое имя интерфейса %q", name)
		}
		if seen[name] {
			return fmt.Errorf("наблюдение DHCP: интерфейс %q указан дважды", name)
		}
		seen[name] = true
	}
	if len(w.Prefixes) == 0 {
		return fmt.Errorf("наблюдение DHCP: нет подсетей локальной сети")
	}
	for _, c := range w.Prefixes {
		if _, ok := parseLAN4(c); !ok {
			return fmt.Errorf("наблюдение DHCP: неверная подсеть %q", c)
		}
	}
	for _, m := range w.OwnMACs {
		if _, ok := parseMAC(m); !ok {
			return fmt.Errorf("наблюдение DHCP: неверный адрес карты %q", m)
		}
	}
	return nil
}

func (w DHCPWatch) Size() int {
	total := 0
	seen := map[string]bool{}
	for _, c := range w.Prefixes {
		n, ok := parseLAN4(c)
		if !ok || seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		ones, bits := n.Mask.Size()
		total += max(1<<(bits-ones)-2, 1)
	}

	return min(max(total, 1), math.MaxUint32)
}

func (w DHCPWatch) Create(fresh, window time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", DHCPWatchTable)
	fmt.Fprintf(&b, "delete table inet %s\n", DHCPWatchTable)
	fmt.Fprintf(&b, "table inet %s {\n", DHCPWatchTable)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr . ipv4_addr\n\t\tsize %d\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n\t}\n",
		DHCPSeenSet, w.Size(), nftDuration(fresh))
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype inet_service\n\t\tflags timeout\n\t}\n", DHCPWindowSet)
	fmt.Fprintf(&b, "\tchain %s {\n", DHCPWatchChain)
	fmt.Fprintf(&b, "\t\ttype filter hook prerouting priority %s; policy accept;\n", dhcpWatchPriority)
	fmt.Fprintf(&b, "\t\t%s\n", w.rule())
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	b.WriteString(windowElement(window))
	return b.String()
}

func (w DHCPWatch) Sync() string {
	return fmt.Sprintf("flush chain inet %s %s\nadd rule inet %s %s %s\n",
		DHCPWatchTable, DHCPWatchChain, DHCPWatchTable, DHCPWatchChain, w.rule())
}

func (w DHCPWatch) Restart(window time.Duration) string {
	return fmt.Sprintf("flush set inet %s %s\nflush set inet %s %s\n",
		DHCPWatchTable, DHCPSeenSet, DHCPWatchTable, DHCPWindowSet) + windowElement(window)
}

func ProbeDHCPWatch() DHCPWatch {
	lan := ProbePlan().LANs[0]
	return DHCPWatch{LANs: []string{lan.Name}, Prefixes: []string{lan.CIDR}, OwnMACs: []string{"00:00:5e:00:53:01"}}
}

func (w DHCPWatch) rule() string {
	var b strings.Builder
	fmt.Fprintf(&b, "iifname %s udp sport 67 udp dport 68 ", quotedSet(w.LANs))
	if macs := w.macs(); len(macs) > 0 {
		fmt.Fprintf(&b, "ether saddr != { %s } ", strings.Join(macs, ", "))
	}
	fmt.Fprintf(&b, "update @%s { ether saddr . ip saddr }", DHCPSeenSet)
	return b.String()
}

func (w DHCPWatch) macs() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range w.OwnMACs {
		if s, ok := parseMAC(m); ok && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func windowElement(window time.Duration) string {
	return fmt.Sprintf("add element inet %s %s { %d timeout %s }\n",
		DHCPWatchTable, DHCPWindowSet, dhcpServerPort, nftDuration(window))
}

func parseMAC(s string) (string, bool) {
	if !macRe.MatchString(s) {
		return "", false
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
}

func parseLAN4(c string) (*net.IPNet, bool) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil || ip.To4() == nil {
		return nil, false
	}
	if _, bits := n.Mask.Size(); bits != 32 {
		return nil, false
	}
	return n, true
}

func nftDuration(d time.Duration) string {
	const day = 24 * time.Hour
	if d > 0 && d%day == 0 {
		return strconv.FormatInt(int64(d/day), 10) + "d"
	}
	s := max((d+time.Second-1)/time.Second, 1)
	return strconv.FormatInt(int64(s), 10) + "s"
}
