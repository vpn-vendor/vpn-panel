package keagen

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

const (
	DefaultValidLifetime = 4 * 24 * 3600
	DefaultRenewFactor   = 50
	DefaultRebindFactor  = 875
	DeclineProbation     = 3600
	LeaseFile            = "/var/lib/kea/kea-leases4.csv"
	LogFile              = "/var/log/kea/kea-dhcp4.log"
)

const (
	poolFirstOffset = 100
	poolLastOffset  = 200
)

var NTPServers = []string{"216.239.35.0", "162.159.200.123"}

var ClientDNS = []string{"9.9.9.9", "149.112.112.112"}

const LocalDomain = "vpn.lan"

const (
	reservationFirstOffset = 20
	reservationLastOffset  = 99
)

type Reservation struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

type LAN struct {
	Name         string        `json:"name"`
	CIDR         string        `json:"cidr"`
	Reservations []Reservation `json:"reservations,omitempty"`
}

type Plan struct {
	LANs          []LAN `json:"lans"`
	ValidLifetime int   `json:"valid_lifetime,omitempty"`

	UseLocalDNS bool `json:"use_local_dns,omitempty"`
}

var ifnameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

func (p *Plan) Validate(knownNames map[string]bool) error {
	if len(p.LANs) == 0 {
		return fmt.Errorf("нет сегментов локальной сети")
	}
	seen := map[string]bool{}
	for _, l := range p.LANs {
		if !ifnameRe.MatchString(l.Name) {
			return fmt.Errorf("недопустимое имя интерфейса %q", l.Name)
		}
		if knownNames != nil && !knownNames[l.Name] {
			return fmt.Errorf("интерфейс %q не существует в системе", l.Name)
		}
		if seen[l.Name] {
			return fmt.Errorf("интерфейс %q указан дважды", l.Name)
		}
		seen[l.Name] = true

		gw, ipnet, err := net.ParseCIDR(l.CIDR)
		if err != nil || gw.To4() == nil {
			return fmt.Errorf("сегмент %q: неверный адрес %q", l.Name, l.CIDR)
		}
		start, end, err := PoolFor(l.CIDR)
		if err != nil {
			return fmt.Errorf("сегмент %q: %w", l.Name, err)
		}
		gwN := ipToUint(gw.To4())
		if gwN >= ipToUint(start) && gwN <= ipToUint(end) {
			return fmt.Errorf("сегмент %q: адрес шлюза %s попадает в пул выдачи %s–%s",
				l.Name, gw, start, end)
		}
		if !ipnet.Contains(gw) {
			return fmt.Errorf("сегмент %q: адрес вне своей подсети", l.Name)
		}
	}
	return nil
}

func PoolFor(cidr string) (net.IP, net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return nil, nil, fmt.Errorf("неверная подсеть")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 30 {
		return nil, nil, fmt.Errorf("подсеть слишком мала для выдачи адресов")
	}
	network := ipToUint(ipnet.IP.To4())
	size := uint32(1) << uint(32-ones)
	firstHost := network + 1
	lastHost := network + size - 2

	start := network + poolFirstOffset
	end := network + poolLastOffset
	if start > lastHost || end <= start {

		start = firstHost + (lastHost-firstHost)/2
		end = lastHost
	}
	if end > lastHost {
		end = lastHost
	}
	if start < firstHost {
		start = firstHost
	}
	if start >= end {
		return nil, nil, fmt.Errorf("подсеть слишком мала для выдачи адресов")
	}
	return uintToIP(start), uintToIP(end), nil
}

func PoolSize(cidr string) int {
	start, end, err := PoolFor(cidr)
	if err != nil {
		return 0
	}
	return int(ipToUint(end)-ipToUint(start)) + 1
}

type optionData struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type pool struct {
	Pool string `json:"pool"`
}

type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
}

type subnet struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Interface    string           `json:"interface"`
	Pools        []pool           `json:"pools"`
	OptionData   []optionData     `json:"option-data"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}

type interfacesConfig struct {
	Interfaces           []string `json:"interfaces"`
	SocketsMaxRetries    int      `json:"service-sockets-max-retries"`
	SocketsRetryWaitTime int      `json:"service-sockets-retry-wait-time"`
}

type leaseDatabase struct {
	Type    string `json:"type"`
	Persist bool   `json:"persist"`
	Name    string `json:"name"`
}

type outputOption struct {
	Output string `json:"output"`
}

type logger struct {
	Name          string         `json:"name"`
	Severity      string         `json:"severity"`
	OutputOptions []outputOption `json:"output_options"`
}

type dhcp4 struct {
	InterfacesConfig interfacesConfig `json:"interfaces-config"`
	LeaseDatabase    leaseDatabase    `json:"lease-database"`
	ValidLifetime    int              `json:"valid-lifetime"`
	RenewTimer       int              `json:"renew-timer"`
	RebindTimer      int              `json:"rebind-timer"`
	DeclineProbation int              `json:"decline-probation-period"`
	Authoritative    bool             `json:"authoritative"`
	Subnet4          []subnet         `json:"subnet4"`
	Loggers          []logger         `json:"loggers"`
}

type keaConfig struct {
	Dhcp4 dhcp4 `json:"Dhcp4"`
}

func (p *Plan) Generate() ([]byte, error) {
	lans := make([]LAN, len(p.LANs))
	copy(lans, p.LANs)
	sort.Slice(lans, func(a, b int) bool { return lans[a].Name < lans[b].Name })

	valid := p.ValidLifetime
	if valid <= 0 {
		valid = DefaultValidLifetime
	}

	cfg := keaConfig{Dhcp4: dhcp4{
		LeaseDatabase:    leaseDatabase{Type: "memfile", Persist: true, Name: LeaseFile},
		ValidLifetime:    valid,
		RenewTimer:       valid * DefaultRenewFactor / 100,
		RebindTimer:      valid * DefaultRebindFactor / 1000,
		DeclineProbation: DeclineProbation,

		Authoritative: true,
		Loggers: []logger{{
			Name:          "kea-dhcp4",
			Severity:      "INFO",
			OutputOptions: []outputOption{{Output: LogFile}},
		}},
	}}

	for i, l := range lans {
		gw, ipnet, err := net.ParseCIDR(l.CIDR)
		if err != nil {
			return nil, fmt.Errorf("сегмент %q: неверный адрес", l.Name)
		}
		_ = gw
		start, end, err := PoolFor(l.CIDR)
		if err != nil {
			return nil, fmt.Errorf("сегмент %q: %w", l.Name, err)
		}

		cfg.Dhcp4.InterfacesConfig.Interfaces = append(
			cfg.Dhcp4.InterfacesConfig.Interfaces, l.Name)
		reservations := make([]keaReservation, 0, len(l.Reservations))
		sortedRes := append([]Reservation(nil), l.Reservations...)
		sort.Slice(sortedRes, func(a, b int) bool { return sortedRes[a].IP < sortedRes[b].IP })
		for _, r := range sortedRes {
			reservations = append(reservations, keaReservation{HWAddress: r.MAC, IPAddress: r.IP})
		}
		cfg.Dhcp4.Subnet4 = append(cfg.Dhcp4.Subnet4, subnet{
			ID:           i + 1,
			Subnet:       ipnet.String(),
			Interface:    l.Name,
			Reservations: reservations,
			Pools:        []pool{{Pool: start.String() + " - " + end.String()}},
			OptionData: []optionData{
				{Name: "routers", Data: gw.String()},
				{Name: "domain-name-servers", Data: clientDNSFor(p.UseLocalDNS, gw.String())},
				{Name: "domain-name", Data: LocalDomain},
				{Name: "ntp-servers", Data: strings.Join(NTPServers, ", ")},
			},
		})
	}

	cfg.Dhcp4.InterfacesConfig.SocketsMaxRetries = 20
	cfg.Dhcp4.InterfacesConfig.SocketsRetryWaitTime = 5000

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func NormalizeMAC(raw string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + 32
		}
		return -1
	}, raw)
	if len(clean) != 12 {
		return "", fmt.Errorf("аппаратный адрес должен состоять из 12 знаков (пример: a4:bb:6d:1f:22:90)")
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = clean[i*2 : i*2+2]
	}
	return strings.Join(parts, ":"), nil
}

func ValidMAC(s string) bool {
	m, err := NormalizeMAC(s)
	return err == nil && m == s
}

func IsRandomMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var first int
	if _, err := fmt.Sscanf(mac[:2], "%x", &first); err != nil {
		return false
	}
	return first&0x02 != 0
}

func ReservationRange(cidr string) (net.IP, net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return nil, nil, fmt.Errorf("неверная подсеть")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 29 {
		return nil, nil, fmt.Errorf("подсеть слишком мала для закреплений")
	}
	network := ipToUint(ipnet.IP.To4())
	size := uint32(1) << uint(32-ones)
	lastHost := network + size - 2
	start := network + reservationFirstOffset
	end := network + reservationLastOffset
	if end > lastHost {
		end = lastHost
	}
	if start >= end {
		start = network + 2
	}
	return uintToIP(start), uintToIP(end), nil
}

func ValidateReservationIP(cidr, addr string) error {
	gw, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("сегмент настроен неверно")
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("неверный адрес %q", addr)
	}
	if !ipnet.Contains(ip) {
		return fmt.Errorf("адрес %s не принадлежит локальной сети %s", addr, ipnet)
	}
	if ip.Equal(gw) {
		return fmt.Errorf("это адрес самого шлюза — выберите другой")
	}
	ones, _ := ipnet.Mask.Size()
	network := ipToUint(ipnet.IP.To4())
	size := uint32(1) << uint(32-ones)
	v := ipToUint(ip.To4())
	if v == network || v == network+size-1 {
		return fmt.Errorf("служебный адрес сети — выберите другой")
	}
	poolStart, poolEnd, err := PoolFor(cidr)
	if err == nil && v >= ipToUint(poolStart) && v <= ipToUint(poolEnd) {
		return fmt.Errorf("адрес %s входит в диапазон автоматической выдачи (%s–%s) — выберите адрес вне него",
			addr, poolStart, poolEnd)
	}
	return nil
}

func clientDNSFor(useLocal bool, gateway string) string {
	if useLocal {
		return gateway
	}
	return strings.Join(ClientDNS, ", ")
}

func ipToUint(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func uintToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}
