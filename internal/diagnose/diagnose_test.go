package diagnose

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/diagfacts"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

func base() Input {
	return Input{
		Now:  time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		LANs: []LAN{{Name: "ens4", CIDR: "192.168.11.1/24"}},
		Leases: []Lease{{IP: "192.168.11.100", MAC: "52:54:00:12:34:10", Hostname: "desktop-example.",
			Until: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}},
		Neighbours: []diagfacts.Neighbour{{IP: "192.168.11.100", MAC: "52:54:00:12:34:10", Dev: "ens4", State: "REACHABLE"}},
		Sets:       map[string][]diagfacts.SetEntry{},
		Vendor:     func(string) string { return "QEMU" },
		Randomized: func(string) bool { return false },
	}
}

func codes(d Device) map[string]string {
	out := map[string]string{}
	for _, x := range d.Diagnoses {
		out[x.Code] = x.Level
	}
	return out
}

func TestCleanProfileIsGreen(t *testing.T) {
	r := Run(base())
	if len(r.Devices) != 1 || r.Devices[0].Level != LevelOK || r.Level != LevelOK {
		t.Fatalf("чистый профиль: %+v", r)
	}
	d := r.Devices[0]
	if d.Hostname != "desktop-example" || !d.Managed || !d.Online || d.Vendor != "QEMU" {
		t.Fatalf("паспорт: %+v", d)
	}
}

func TestForeignDNSProfile(t *testing.T) {
	in := base()
	in.Sets[nftgen.SetForeignDNS] = []diagfacts.SetEntry{{IP: "192.168.11.100", Packets: 2, Expires: nftgen.DiagSetTimeoutSec - 600}}
	r := Run(in)
	if codes(r.Devices[0])["foreign_dns"] != LevelError || r.Devices[0].Level != LevelError {
		t.Fatalf("foreign-dns: %+v", r.Devices[0].Diagnoses)
	}
	if !strings.Contains(r.Devices[0].Diagnoses[0].Title, "10 мин назад") {
		t.Fatalf("возраст попадания: %s", r.Devices[0].Diagnoses[0].Title)
	}
}

func TestNoDhcpProfileIsStatic(t *testing.T) {
	in := base()
	in.LANs[0].PoolFrom, in.LANs[0].PoolTo = net.ParseIP("192.168.11.100"), net.ParseIP("192.168.11.200")
	in.Leases = nil
	in.Neighbours = []diagfacts.Neighbour{{IP: "192.168.11.77", MAC: "52:54:00:12:34:10", Dev: "ens4", State: "REACHABLE"}}
	r := Run(in)
	if codes(r.Devices[0])["static_ip"] != LevelWarn || r.Devices[0].Managed {
		t.Fatalf("no-dhcp: %+v", r.Devices[0])
	}

	in.Neighbours[0].IP = "192.168.11.100"
	r = Run(in)
	if c := codes(r.Devices[0]); c["unknown_lease"] != LevelInfo || c["static_ip"] != "" {
		t.Fatalf("адрес из пула без аренды: %v", c)
	}
}

func TestTeredoProfile(t *testing.T) {
	in := base()
	in.Sets[nftgen.SetIPv6Tunnel] = []diagfacts.SetEntry{{IP: "192.168.11.100", Packets: 7}}
	if codes(Run(in).Devices[0])["ipv6_tunnel"] != LevelError {
		t.Fatal("teredo → ipv6_tunnel error")
	}
}

func TestTweakerAndNoTimeAreInvisible(t *testing.T) {

	if r := Run(base()); r.Devices[0].Level != LevelOK {
		t.Fatal("нет фактов — нет диагнозов")
	}
}

func TestPublicProfileArpStillAnswers(t *testing.T) {
	in := base()
	in.Probe = map[string]diagfacts.ProbeResult{"192.168.11.100": {IP: "192.168.11.100", Sent: 5, Received: 5, AvgMs: 0.9, JitterMs: 0.1}}
	if r := Run(in); r.Devices[0].Level != LevelOK || r.Devices[0].Probe == nil {
		t.Fatalf("проба на уровне ARP отвечает при «Общедоступной» — диагнозов нет: %+v", r.Devices[0])
	}
}

func TestProbeQualityAndSilence(t *testing.T) {
	in := base()
	in.Probe = map[string]diagfacts.ProbeResult{"192.168.11.100": {IP: "192.168.11.100", Sent: 5, Received: 4, JitterMs: 12}}
	if codes(Run(in).Devices[0])["lan_quality"] != LevelError {
		t.Fatal("потери 20 % / джиттер 12 мс → lan_quality error")
	}
	in.Probe = map[string]diagfacts.ProbeResult{"192.168.11.100": {IP: "192.168.11.100", Sent: 5, Received: 0}}
	if codes(Run(in).Devices[0])["probe_silent"] != LevelWarn {
		t.Fatal("без ответов → probe_silent warn")
	}
}

func TestOwnVPNUpdatesAndRandomMAC(t *testing.T) {
	in := base()
	in.Sets[nftgen.SetOwnVPN] = []diagfacts.SetEntry{{IP: "192.168.11.100", Packets: 30}}
	in.Sets[nftgen.SetUpdatesP2P] = []diagfacts.SetEntry{{IP: "192.168.11.100", Packets: 3}}
	in.Randomized = func(string) bool { return true }
	c := codes(Run(in).Devices[0])
	if c["own_vpn"] != LevelError || c["updates_p2p"] != LevelWarn || c["random_mac"] != LevelInfo {
		t.Fatalf("диагнозы: %v", c)
	}
}

func TestMACFlapping(t *testing.T) {
	in := base()
	in.Leases = append(in.Leases, Lease{IP: "192.168.11.101", MAC: "52:54:00:12:34:11", Hostname: "DESKTOP-EXAMPLE"})
	r := Run(in)
	if len(r.Devices) != 2 || codes(r.Devices[0])["mac_flapping"] != LevelWarn {
		t.Fatalf("одно имя, два MAC: %+v", r.Devices)
	}
}

func TestNetworkLinkDiagnoses(t *testing.T) {
	in := base()
	in.Links = []diagfacts.LinkStats{{Name: "ens4", SpeedMbit: 100, Duplex: "half", RxCRC: 5, Collisions: 2}}
	r := Run(in)
	got := map[string]bool{}
	for _, d := range r.Network {
		got[d.Code] = true
	}
	if !got["link_speed"] || !got["link_half_duplex"] || !got["link_errors"] || r.Level != LevelError {
		t.Fatalf("сеть: %+v", r.Network)
	}
	in.Links = []diagfacts.LinkStats{{Name: "ens4", SpeedMbit: -1, Duplex: "unknown"}}
	if r := Run(in); len(r.Network) != 0 {
		t.Fatal("виртуальная карта без данных — без диагнозов")
	}
}

func TestExcludeAndSorting(t *testing.T) {
	in := base()
	in.Exclude = map[string]bool{"192.168.11.254": true}
	in.Neighbours = append(in.Neighbours,
		diagfacts.Neighbour{IP: "192.168.11.254", MAC: "52:54:00:70:1d:a4", State: "STALE"},
		diagfacts.Neighbour{IP: "192.168.11.50", MAC: "aa:bb:cc:dd:ee:01", State: "REACHABLE"})
	r := Run(in)
	if len(r.Devices) != 2 || r.Devices[0].IP != "192.168.11.50" {
		t.Fatalf("исключение и сортировка (проблемные первыми): %+v", r.Devices)
	}
}
