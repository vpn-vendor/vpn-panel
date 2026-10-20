package nftgen

import "runtime"

func ProbePlan() FirewallPlan {
	return FirewallPlan{
		WANs:       []string{"vp-wan0"},
		LANs:       []FirewallLAN{{Name: "vp-probe0", CIDR: "192.0.2.1/24"}},
		HiddenMode: true,
		IPv6:       true,
		Tunnel: &FirewallTunnel{
			Iface: "vp-tun0", Endpoint: "198.51.100.10", EndpointPort: 1194, EndpointProto: "udp",

			Mark:    1,
			Address: "10.8.0.2",
		},
		Panel: &FirewallPanel{
			Ports: []int{443, 80},

			PerSourceConns:    PanelNewBurst,
			TotalNewPerSecond: PanelTotalNewPerSecond(runtime.GOMAXPROCS(0)),
		},
	}
}
