package dhcp

import (
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
)

const PoolWarnPercent = 80

type Service struct {
}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) BuildPlan(localDNS bool) keagen.Plan {
	var rows []models.Interface
	_ = facades.Orm().Query().Where("role", "lan").Find(&rows)
	reservations := s.Reservations()
	var plan keagen.Plan
	plan.UseLocalDNS = localDNS
	for _, r := range rows {
		if r.IPv4CIDR == "" {
			continue
		}
		lan := keagen.LAN{Name: r.Name, CIDR: r.IPv4CIDR}
		_, ipnet, err := net.ParseCIDR(r.IPv4CIDR)
		if err == nil {
			for _, res := range reservations {

				if ip := net.ParseIP(res.IP); ip != nil && ipnet.Contains(ip) {
					lan.Reservations = append(lan.Reservations,
						keagen.Reservation{MAC: res.MAC, IP: res.IP})
				}
			}
		}
		plan.LANs = append(plan.LANs, lan)
	}
	return plan
}

func (s *Service) Reservations() []models.DhcpReservation {
	var rows []models.DhcpReservation
	_ = facades.Orm().Query().OrderBy("ip").Find(&rows)
	return rows
}

func (s *Service) LANSegments() []models.Interface {
	var rows []models.Interface
	_ = facades.Orm().Query().Where("role", "lan").Find(&rows)
	return rows
}

func (s *Service) NextFreeReservationIP(cidr string) (string, error) {
	start, end, err := keagen.ReservationRange(cidr)
	if err != nil {
		return "", err
	}
	taken := map[string]bool{}
	for _, r := range s.Reservations() {
		taken[r.IP] = true
	}
	for ip := start.To4(); !ipAfter(ip, end.To4()); ip = nextIP(ip) {
		if !taken[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", errors.New("свободные адреса для закрепления закончились")
}

func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func ipAfter(a, b net.IP) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func (s *Service) Apply(plan keagen.Plan) (bool, string, error) {
	resp, err := s.client().Call("dhcp.apply", map[string]any{"plan": plan})
	if err != nil {
		return false, "", err
	}
	if resp.Error != nil {
		return false, "", resp.Error
	}
	var r struct {
		Changed bool   `json:"changed"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return false, "", err
	}
	return r.Changed, r.State, nil
}

type Lease struct {
	Address  string
	MAC      string
	Hostname string
	Until    time.Time
}

func (s *Service) Leases() (string, []Lease, error) {
	resp, err := s.client().Call("dhcp.leases", map[string]any{})
	if err != nil {
		return "", nil, err
	}
	if resp.Error != nil {
		return "", nil, resp.Error
	}
	var r struct {
		Service string `json:"service"`
		Leases  []struct {
			Address  string `json:"address"`
			MAC      string `json:"mac"`
			Hostname string `json:"hostname"`
			Expires  int64  `json:"expires"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return "", nil, err
	}
	list := make([]Lease, 0, len(r.Leases))
	for _, l := range r.Leases {
		list = append(list, Lease{
			Address: l.Address, MAC: l.MAC, Hostname: l.Hostname,
			Until: time.Unix(l.Expires, 0),
		})
	}
	return r.Service, list, nil
}

type PoolStat struct {
	Name    string
	CIDR    string
	Size    int
	Used    int
	Percent int

	Step int
}

func (s *Service) PoolStats(plan keagen.Plan, leases []Lease) []PoolStat {
	stats := make([]PoolStat, 0, len(plan.LANs))
	for _, l := range plan.LANs {
		_, ipnet, err := net.ParseCIDR(l.CIDR)
		if err != nil {
			continue
		}
		used := 0
		for _, lease := range leases {
			if ip := net.ParseIP(lease.Address); ip != nil && ipnet.Contains(ip) {
				used++
			}
		}
		size := keagen.PoolSize(l.CIDR)
		percent := 0
		if size > 0 {
			percent = used * 100 / size
		}
		stats = append(stats, PoolStat{
			Name: l.Name, CIDR: l.CIDR, Size: size, Used: used, Percent: percent,
			Step: percent / 5 * 5,
		})
	}
	return stats
}
