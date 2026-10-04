package ovpngen

import (
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const ID vpndriver.Protocol = "openvpn"

const Iface = "ovpn-vpn0"

const (
	OverheadIPv4 = 52
	OverheadIPv6 = 72
)

var Descriptor = vpndriver.Descriptor{
	ID:         ID,
	Label:      "OpenVPN",
	Iface:      Iface,
	Hint:       "OpenVPN (со строкой remote и сертификатами внутри)",
	FileExts:   []string{".ovpn", ".conf"},
	Transports: []string{vpndriver.TransportUDP, vpndriver.TransportTCP},
	Packages:   []string{"openvpn"},
	Keywords:   []string{"openvpn", "ovpn"},
	Marks:      marks,
	Passport:   passport,
	CheckMeta:  checkMeta,
}

func marks(line string) bool {
	return strings.HasPrefix(line, "remote ") || line == "client" || line == "tls-client" ||
		strings.HasPrefix(line, "<ca>") || strings.HasPrefix(line, "<cert>") ||
		strings.HasPrefix(line, "proto ") || strings.HasPrefix(line, "dev ")
}

func passport(transport string) vpndriver.Passport {
	if transport == "" {
		transport = vpndriver.TransportUDP
	}
	return vpndriver.Passport{
		Protocol: ID, Transport: transport,
		KernelDataPlane: true, UsesAES: true,
		SetsMark: false, ManagesRoutes: false, ServerPushes: true,
		ProbeCandidates: []string{"pushed_gateway", "admin"},
		AddressAtImport: false, Liveness: vpndriver.LivenessProcess, ClockSensitive: true,

		ProgressPeriod: 10 * time.Second, SelfHealBudget: 120 * time.Second,
		CanPause:     true,
		OverheadIPv4: OverheadIPv4, OverheadIPv6: OverheadIPv6,
	}
}

func checkMeta(m vpndriver.Meta) fielderr.List {
	var errs fielderr.List
	for _, f := range []struct {
		path  string
		empty bool
	}{{"peer_key", m.PeerKey == ""}, {"addresses", len(m.Addresses) == 0}, {"allowed_ips", len(m.AllowedIPs) == 0}} {
		if !f.empty {
			errs.Add(f.path, "у OpenVPN это поле пусто: значение даёт сервер при подключении")
		}
	}
	return errs
}
