package netplangen

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func MaskToPrefix(mask string) (int, bool) {
	ip := net.ParseIP(strings.TrimSpace(mask))
	if ip == nil || ip.To4() == nil {
		return 0, false
	}
	ones, bits := net.IPMask(ip.To4()).Size()
	if bits != 32 {
		return 0, false
	}
	return ones, true
}

func PrefixToMask(prefix int) (string, bool) {
	if prefix < 0 || prefix > 32 {
		return "", false
	}
	m := net.CIDRMask(prefix, 32)
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), true
}

func ParseAddrField(s string) (addr string, prefix int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", -1, false
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host := s[:i]
		p, err := strconv.Atoi(s[i+1:])
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.To4() == nil || p < 0 || p > 32 {
			return "", -1, false
		}
		return host, p, true
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", -1, false
	}
	return s, -1, true
}

func SuggestPrefix(addr, gateway string) (prefix int, reason string, ok bool) {
	ip := net.ParseIP(strings.TrimSpace(addr))
	gw := net.ParseIP(strings.TrimSpace(gateway))
	if ip == nil || ip.To4() == nil || gw == nil || gw.To4() == nil {
		return 0, "", false
	}
	for p := 24; p >= 8; p-- {
		if sameNet(ip, gw, p) {
			return p, fmt.Sprintf("при /%d адрес %s и шлюз %s в одной сети", p, addr, gateway), true
		}
	}

	return 0, "адрес и шлюз в разных сетях — уточните маску у провайдера", false
}

func GatewayConsistent(addr string, prefix int, gateway string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	gw := net.ParseIP(strings.TrimSpace(gateway))
	if ip == nil || gw == nil || ip.To4() == nil || gw.To4() == nil {
		return false
	}
	if prefix >= 31 {
		return true
	}
	return sameNet(ip, gw, prefix)
}

func sameNet(a, b net.IP, prefix int) bool {
	mask := net.CIDRMask(prefix, 32)
	return a.To4().Mask(mask).Equal(b.To4().Mask(mask))
}
