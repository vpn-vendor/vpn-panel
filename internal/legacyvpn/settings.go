package legacyvpn

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	MethodDHCP   = "dhcp"
	MethodStatic = "static"
	MethodPPPoE  = "pppoe"
)

const (
	ProtocolOpenVPN   = "openvpn"
	ProtocolWireGuard = "wireguard"
)

type Settings struct {
	WAN WAN `json:"wan"`
	LAN LAN `json:"lan"`

	DHCP DHCP `json:"dhcp"`

	VPN *VPN `json:"vpn,omitempty"`

	Missing []Missing `json:"missing"`
}

type WAN struct {
	Card    string   `json:"card"`
	Method  string   `json:"method"`
	CIDR    string   `json:"cidr,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`

	PPPoEUser     string `json:"pppoe_user,omitempty"`
	PPPoEPassword bool   `json:"pppoe_password,omitempty"`
}

type LAN struct {
	Card string `json:"card"`
	CIDR string `json:"cidr"`
}

type DHCP struct {
	Subnet     string `json:"subnet,omitempty"`
	RangeStart string `json:"range_start,omitempty"`
	RangeEnd   string `json:"range_end,omitempty"`
	Lease      int    `json:"lease,omitempty"`
}

type VPN struct {
	Protocol string `json:"protocol"`
	Endpoint string `json:"endpoint,omitempty"`
	Path     string `json:"path"`
}

type Missing struct {
	What string `json:"what"`
	Why  string `json:"why"`
}

const (
	iscDefault = "/etc/default/isc-dhcp-server"
	dhcpdConf  = "/etc/dhcp/dhcpd.conf"
)

const (
	whatWANCard = "карта в интернет"
	whatWAN     = "способ подключения к провайдеру"
	whatLAN     = "карта в офис и адрес шлюза"
	whatDHCP    = "диапазон выдачи адресов"
	whatVPN     = "подключение VPN"
)

type npEthernet struct {
	DHCP4       any       `yaml:"dhcp4"`
	Addresses   []string  `yaml:"addresses"`
	Gateway4    string    `yaml:"gateway4"`
	Optional    bool      `yaml:"optional"`
	Routes      []npRoute `yaml:"routes"`
	Nameservers struct {
		Addresses []string `yaml:"addresses"`
	} `yaml:"nameservers"`
}

type npRoute struct {
	To  string `yaml:"to"`
	Via string `yaml:"via"`
}

type npFile struct {
	Network struct {
		Ethernets map[string]npEthernet `yaml:"ethernets"`
	} `yaml:"network"`
}

func ReadSettings(root string) Settings {
	r := reader{root: root}
	var s Settings
	eth, ok := r.netplan(&s)
	lanCard := r.lanCard(eth)
	r.pppoe(&s)
	if s.WAN.Method == "" && ok {
		r.wanFromNetplan(&s, eth, lanCard)
	}
	if s.WAN.Method == "" {
		s.miss(whatWAN, "в настройках старого шлюза не найдено ни автоматического адреса, ни постоянного, ни PPPoE")
	}
	r.lan(&s, eth, lanCard)
	r.dhcp(&s)
	r.vpn(&s)
	return s
}

type reader struct{ root string }

func (r reader) read(p string) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(r.root, p)) //nolint:gosec
	return data, err == nil
}

func (s *Settings) miss(what, why string) {
	s.Missing = append(s.Missing, Missing{What: what, Why: why})
}

func (r reader) netplan(s *Settings) (map[string]npEthernet, bool) {
	data, ok := r.read(scriptNetplan)
	if !ok {
		s.miss(whatWANCard, "файла настроек сети старого шлюза нет")
		return nil, false
	}
	var f npFile
	if err := yaml.Unmarshal(data, &f); err != nil || len(f.Network.Ethernets) == 0 {
		s.miss(whatWANCard, "файл настроек сети старого шлюза не разобран")
		return nil, false
	}
	return f.Network.Ethernets, true
}

func (r reader) lanCard(eth map[string]npEthernet) string {
	data, ok := r.read(iscDefault)
	if !ok {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		for _, key := range []string{"INTERFACESv4=", "INTERFACES="} {
			if v, found := strings.CutPrefix(t, key); found {
				if card := strings.Fields(strings.Trim(v, `"'`)); len(card) > 0 && validCard(card[0]) {
					return card[0]
				}
			}
		}
	}
	_ = eth
	return ""
}

var cardRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

func validCard(c string) bool { return cardRe.MatchString(c) }

func dhcp4On(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes")
	}
	return false
}

func (r reader) wanFromNetplan(s *Settings, eth map[string]npEthernet, lanCard string) {
	for _, name := range sortedKeys(eth) {
		e := eth[name]
		if name == lanCard || !validCard(name) {
			continue
		}
		if dhcp4On(e.DHCP4) {
			s.WAN = WAN{Card: name, Method: MethodDHCP}
			return
		}
		gw := e.Gateway4
		for _, rt := range e.Routes {
			if (rt.To == "default" || rt.To == "0.0.0.0/0") && rt.Via != "" {
				gw = rt.Via
			}
		}
		if gw == "" || len(e.Addresses) == 0 {
			continue
		}
		if _, err := netip.ParsePrefix(e.Addresses[0]); err != nil {
			s.miss(whatWAN, "постоянный адрес карты "+name+" записан непонятно: "+e.Addresses[0])
			return
		}
		if _, err := netip.ParseAddr(gw); err != nil {
			s.miss(whatWAN, "шлюз провайдера записан непонятно: "+gw)
			return
		}
		w := WAN{Card: name, Method: MethodStatic, CIDR: e.Addresses[0], Gateway: gw}
		for _, d := range e.Nameservers.Addresses {
			if _, err := netip.ParseAddr(d); err == nil {
				w.DNS = append(w.DNS, d)
			}
		}
		s.WAN = w
		return
	}
}

var (
	peerPluginRe = regexp.MustCompile(`(?m)^plugin\s+(?:rp-)?pppoe\.so\s+(?:nic-)?(\S+)\s*$`)
	peerUserRe   = regexp.MustCompile(`(?m)^user\s+"?([^"\n]*?)"?\s*$`)
)

func (r reader) pppoe(s *Settings) {
	data, ok := r.read(PPPoEPeer)
	if !ok {
		return
	}
	card := peerPluginRe.FindSubmatch(data)
	user := peerUserRe.FindSubmatch(data)
	if card == nil || user == nil || !validCard(string(card[1])) || strings.TrimSpace(string(user[1])) == "" {
		s.miss(whatWAN, "подключение PPPoE старого шлюза записано непонятно: нет карты или логина")
		return
	}
	s.WAN = WAN{Card: string(card[1]), Method: MethodPPPoE, PPPoEUser: strings.TrimSpace(string(user[1]))}
	if secrets, ok := r.read(pppdChapFile); ok {
		_, s.WAN.PPPoEPassword = secretFor(secrets, s.WAN.PPPoEUser)
	}
	if !s.WAN.PPPoEPassword {
		s.miss("пароль PPPoE", "в секретах pppd нет строки для логина "+s.WAN.PPPoEUser+": пароль придётся ввести")
	}
}

const pppdChapFile = "/etc/ppp/chap-secrets" //nolint:gosec

func secretFor(data []byte, user string) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		f := splitSecret(t)
		if len(f) >= 3 && f[0] == user {
			return f[2], true
		}
	}
	return "", false
}

func splitSecret(t string) []string {
	var out []string
	var cur strings.Builder
	quoted, have := false, false
	for _, c := range t {
		switch {
		case c == '"':
			quoted, have = !quoted, true
		case (c == ' ' || c == '\t') && !quoted:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

func ReadPPPoEPassword(root, user string) (string, bool) {
	data, ok := reader{root: root}.read(pppdChapFile)
	if !ok || user == "" {
		return "", false
	}
	return secretFor(data, user)
}

func (r reader) lan(s *Settings, eth map[string]npEthernet, lanCard string) {
	if eth == nil {
		s.miss(whatLAN, "файла настроек сети старого шлюза нет")
		return
	}
	if lanCard == "" {

		for _, name := range sortedKeys(eth) {
			e := eth[name]
			if name != s.WAN.Card && validCard(name) && len(e.Addresses) > 0 && e.Gateway4 == "" && len(e.Routes) == 0 && !dhcp4On(e.DHCP4) {
				lanCard = name
				break
			}
		}
	}
	e, ok := eth[lanCard]
	if lanCard == "" || !ok || len(e.Addresses) == 0 {
		s.miss(whatLAN, "карта офиса в настройках старого шлюза не найдена")
		return
	}
	if _, err := netip.ParsePrefix(e.Addresses[0]); err != nil {
		s.miss(whatLAN, "адрес офиса записан непонятно: "+e.Addresses[0])
		return
	}
	s.LAN = LAN{Card: lanCard, CIDR: e.Addresses[0]}
}

var (
	subnetRe = regexp.MustCompile(`(?m)^\s*subnet\s+(\S+)\s+netmask\s+(\S+)\s*\{`)
	rangeRe  = regexp.MustCompile(`(?m)^\s*range\s+(\S+)\s+(\S+)\s*;`)
	leaseRe  = regexp.MustCompile(`(?m)^\s*default-lease-time\s+(\d+)\s*;`)
)

func (r reader) dhcp(s *Settings) {
	data, ok := r.read(dhcpdConf)
	if !ok {
		s.miss(whatDHCP, "файла настроек старого сервера DHCP нет")
		return
	}
	sub := subnetRe.FindSubmatch(data)
	rng := rangeRe.FindSubmatch(data)
	if sub == nil || rng == nil {
		s.miss(whatDHCP, "в настройках старого сервера DHCP нет подсети или диапазона")
		return
	}
	mask := net.ParseIP(string(sub[2]))
	ip := net.ParseIP(string(sub[1]))
	if ip == nil || mask == nil || mask.To4() == nil {
		s.miss(whatDHCP, "подсеть старого сервера DHCP записана непонятно")
		return
	}
	ones, _ := net.IPMask(mask.To4()).Size()
	d := DHCP{Subnet: ip.String() + "/" + strconv.Itoa(ones), RangeStart: string(rng[1]), RangeEnd: string(rng[2])}
	if l := leaseRe.FindSubmatch(data); l != nil {
		d.Lease, _ = strconv.Atoi(string(l[1]))
	}
	for _, a := range []string{d.RangeStart, d.RangeEnd} {
		if _, err := netip.ParseAddr(a); err != nil {
			s.miss(whatDHCP, "диапазон старого сервера DHCP записан непонятно: "+a)
			return
		}
	}
	s.DHCP = d
}

var (
	ovpnRemoteRe = regexp.MustCompile(`(?m)^\s*remote\s+(\S+)(?:\s+(\d+))?`)
	wgEndpointRe = regexp.MustCompile(`(?m)^\s*Endpoint\s*=\s*(\S+)`)
)

func (r reader) vpn(s *Settings) {
	if data, ok := r.read(openvpnConf); ok {
		v := &VPN{Protocol: ProtocolOpenVPN, Path: openvpnConf}
		if m := ovpnRemoteRe.FindSubmatch(data); m != nil {
			v.Endpoint = string(m[1])
			if len(m[2]) > 0 {
				v.Endpoint += ":" + string(m[2])
			}
		}
		s.VPN = v
		return
	}
	if data, ok := r.read(wireguardConf); ok {
		v := &VPN{Protocol: ProtocolWireGuard, Path: wireguardConf}
		if m := wgEndpointRe.FindSubmatch(data); m != nil {
			v.Endpoint = string(m[1])
		}
		s.VPN = v
	}
}

func sortedKeys(m map[string]npEthernet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func ProtocolWord(p string) string {
	switch p {
	case ProtocolOpenVPN:
		return "OpenVPN"
	case ProtocolWireGuard:
		return "WireGuard"
	}
	return p
}

func VPNConfigPath(protocol string) string {
	switch protocol {
	case ProtocolOpenVPN:
		return openvpnConf
	case ProtocolWireGuard:
		return wireguardConf
	}
	return ""
}
