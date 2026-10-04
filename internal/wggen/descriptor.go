package wggen

import (
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const ID vpndriver.Protocol = "wireguard"

const Iface = "wg-vpn0"

const (
	OverheadIPv4 = 60
	OverheadIPv6 = 80
)

var Descriptor = vpndriver.Descriptor{
	ID:         ID,
	Label:      "WireGuard",
	Iface:      Iface,
	Hint:       "WireGuard (с разделами [Interface] и [Peer])",
	FileExts:   []string{".conf"},
	Transports: []string{vpndriver.TransportUDP},
	Packages:   []string{"wireguard-tools"},
	Keywords:   []string{"wireguard", "conf"},
	Marks:      func(line string) bool { return line == "[interface]" || line == "[peer]" },
	Passport:   passport,
	CheckMeta:  checkMeta,
}

func passport(string) vpndriver.Passport {
	return vpndriver.Passport{
		Protocol: ID, Transport: vpndriver.TransportUDP,
		KernelDataPlane: true, UsesAES: false,
		SetsMark: true, ManagesRoutes: false, ServerPushes: false,
		ProbeCandidates: []string{"admin", "subnet_first"},
		AddressAtImport: true, Liveness: vpndriver.LivenessHandshake, ClockSensitive: false,

		ProgressPeriod: 120 * time.Second, SelfHealBudget: 90 * time.Second,
		OverheadIPv4: OverheadIPv4, OverheadIPv6: OverheadIPv6,
	}
}

func checkMeta(m vpndriver.Meta) fielderr.List {
	var errs fielderr.List
	if k, err := base64.StdEncoding.DecodeString(m.PeerKey); err != nil || len(k) != 32 {
		errs.Add("peer_key", "ключ сервера WireGuard — 32 байта в base64")
	}
	if !prefixes(m.Addresses) {
		errs.Add("addresses", "адреса канала — список адресов с префиксом через запятую")
	}
	if !prefixes(m.AllowedIPs) {
		errs.Add("allowed_ips", "сети канала — список сетей с префиксом через запятую")
	}
	return errs
}

func prefixes(list []string) bool {
	if len(list) == 0 {
		return false
	}
	for _, p := range list {
		if _, err := netip.ParsePrefix(p); err != nil {
			return false
		}
	}
	return true
}
