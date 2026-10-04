package bindset

import (
	"net"
	"net/netip"
	"sort"
)

type Mode string

const (
	ModeDev      Mode = "dev"
	ModeRoles    Mode = "roles"
	ModePreRoles Mode = "pre-roles"
)

const Loopback = "127.0.0.1"

const Wildcard = "0.0.0.0"

type Interface struct {
	Name  string
	CIDRs []string
}

type Addr struct {
	IP    string
	Iface string
}

type Set struct {
	Mode  Mode
	Addrs []Addr
}

func (s Set) IPs() []string {
	out := make([]string, 0, len(s.Addrs))
	for _, a := range s.Addrs {
		out = append(out, a.IP)
	}
	return out
}

func Compute(dev bool, lanCIDRs []string, ifaces []Interface) Set {
	if dev {
		return Set{Mode: ModeDev, Addrs: []Addr{{IP: Wildcard, Iface: "*"}}}
	}
	set := Set{Addrs: []Addr{{IP: Loopback, Iface: "lo"}}}
	seen := map[string]bool{Loopback: true}
	add := func(ip, iface string) {
		if !seen[ip] {
			seen[ip] = true
			set.Addrs = append(set.Addrs, Addr{IP: ip, Iface: iface})
		}
	}

	var lanIPs []Addr
	for _, cidr := range lanCIDRs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil || ip.To4() == nil {
			continue
		}
		lanIPs = append(lanIPs, Addr{IP: ip.String(), Iface: ifaceOf(ifaces, ip)})
	}
	if len(lanIPs) > 0 {
		set.Mode = ModeRoles
		for _, a := range lanIPs {
			add(a.IP, a.Iface)
		}
		sortAddrs(set.Addrs)
		return set
	}

	set.Mode = ModePreRoles
	for _, iface := range ifaces {
		for _, cidr := range iface.CIDRs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if PreRoleAllowed(ip) {
				add(ip.String(), iface.Name)
			}
		}
	}
	sortAddrs(set.Addrs)
	return set
}

func PreRoleAllowed(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || ip.IsLoopback() {
		return false
	}
	addr, ok := netip.AddrFromSlice(v4)
	if !ok {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func ifaceOf(ifaces []Interface, ip net.IP) string {
	for _, iface := range ifaces {
		for _, cidr := range iface.CIDRs {
			if cur, _, err := net.ParseCIDR(cidr); err == nil && cur.Equal(ip) {
				return iface.Name
			}
		}
	}
	return ""
}

func sortAddrs(addrs []Addr) {
	sort.SliceStable(addrs, func(i, j int) bool {
		if addrs[i].IP == Loopback {
			return true
		}
		if addrs[j].IP == Loopback {
			return false
		}
		return addrs[i].IP < addrs[j].IP
	})
}

func LocalInterfaces() []Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := Interface{Name: iface.Name}
		for _, a := range addrs {
			entry.CIDRs = append(entry.CIDRs, a.String())
		}
		out = append(out, entry)
	}
	return out
}
