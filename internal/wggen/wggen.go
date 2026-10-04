package wggen

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const TunnelIface = Iface

const DefaultFwmark = vpndriver.Mark

const (
	MinMTU      = vpndriver.MinMTU
	MaxMTU      = vpndriver.MaxMTU
	FallbackMTU = 1420
)

const DefaultKeepalive = 25

type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	EndpointHost        string   `json:"endpoint_host"`
	EndpointPort        int      `json:"endpoint_port"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type Profile struct {
	PrivateKey string   `json:"private_key"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Peer       Peer     `json:"peer"`

	KeepaliveAssumed bool `json:"keepalive_assumed,omitempty"`
}

type Meta = vpndriver.Meta

func (p *Profile) Meta() Meta {
	return Meta{
		Protocol:     ID,
		Transport:    vpndriver.TransportUDP,
		Addresses:    append([]string(nil), p.Addresses...),
		PeerKey:      p.Peer.PublicKey,
		AllowedIPs:   append([]string(nil), p.Peer.AllowedIPs...),
		EndpointHost: p.Peer.EndpointHost,
		EndpointPort: p.Peer.EndpointPort,
		ConfigDNS:    append([]string(nil), p.DNS...),
		ConfigMTU:    p.MTU,
		Keepalive:    p.Peer.PersistentKeepalive,
		FullTunnel:   p.FullTunnel(),

		VoiceFit: true,
	}
}

func (p *Profile) FullTunnel() bool {
	for _, a := range p.Peer.AllowedIPs {
		if a == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func (p *Profile) TunnelIPv4() string {
	for _, a := range p.Addresses {
		if ip, _, err := net.ParseCIDR(a); err == nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

var scriptKeys = map[string]bool{
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

var formatKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"j1": true, "j2": true, "j3": true, "itime": true,
}

var managedKeys = map[string]string{
	"table":      "таблица маршрутов",
	"fwmark":     "служебная метка пакетов",
	"listenport": "номер порта туннеля",
	"saveconfig": "автосохранение файла",
}

var (
	sectionRe = regexp.MustCompile(`^\[([A-Za-z]+)\]$`)
)

type ParseError struct{ Text string }

func (e *ParseError) Error() string { return e.Text }

func fail(format string, args ...any) error {
	return &ParseError{Text: fmt.Sprintf(format, args...)}
}

const MaxConfigBytes = vpndriver.MaxConfigBytes

func Parse(text string) (*Profile, []string, error) {
	if len(text) > MaxConfigBytes {
		return nil, nil, fail("файл слишком большой для конфигурации подключения — проверьте, что выбран нужный файл")
	}
	var (
		p        Profile
		warnings []string
		section  string
		peers    int
		unknown  []string
	)
	seen := map[string]bool{}

	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			section = strings.ToLower(m[1])
			switch section {
			case "interface":
			case "peer":
				peers++
			default:
				warnings = append(warnings, "раздел «"+m[1]+"» этой версией панели не поддерживается и пропущен")
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, nil, fail("строка %d файла не похожа на настройку — проверьте, что выбран файл подключения", n+1)
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		value := strings.TrimSpace(line[eq+1:])
		if i := strings.IndexAny(value, "#;"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}

		if scriptKeys[key] {
			return nil, nil, fail("в файле есть команда «%s», которую сервер выполнил бы с полными правами. Такие файлы панель не принимает — запросите у поставщика конфигурацию без встроенных команд", strings.TrimSpace(line[:eq]))
		}

		if formatKeys[key] {
			return nil, nil, fail("этот файл — для защищённого канала с маскировкой трафика (параметр «%s»). Эта версия панели работает с обычным защищённым каналом: если импортировать файл как есть, канал поднимется, но работать не будет. Запросите у поставщика обычную конфигурацию", strings.TrimSpace(line[:eq]))
		}
		if human, ok := managedKeys[key]; ok {
			warnings = append(warnings, "файл задаёт "+human+" — этим распоряжается сама панель, значение из файла пропущено")
			continue
		}
		if section == "" {
			return nil, nil, fail("строка %d стоит до начала раздела — проверьте, что выбран файл подключения", n+1)
		}
		if seen[section+"."+key] && section == "interface" {
			return nil, nil, fail("настройка «%s» встречается в файле дважды — исправьте файл или запросите его заново", strings.TrimSpace(line[:eq]))
		}
		seen[section+"."+key] = true

		if section == "peer" && peers > 1 {
			continue
		}

		switch {
		case section == "interface" && key == "privatekey":
			if err := checkKey(value); err != nil {
				return nil, nil, fail("секретный ключ в файле повреждён — запросите конфигурацию заново")
			}
			p.PrivateKey = value
		case section == "interface" && key == "address":
			list, err := parseCIDRList(value)
			if err != nil {
				return nil, nil, fail("адрес в файле записан неверно: %s", err)
			}
			p.Addresses = list
		case section == "interface" && key == "dns":

			list, domains, bad := parseDNSList(value)
			if bad != "" {
				warnings = append(warnings, "в строке серверов имён есть непонятное значение «"+bad+"» — панель его пропустит")
			}
			if len(domains) > 0 {
				warnings = append(warnings, "файл просит домен поиска «"+strings.Join(domains, ", ")+"» — именами в офисе распоряжается сам шлюз, поэтому домен не применяется")
			}
			p.DNS = list
		case section == "interface" && key == "mtu":
			mtu, err := strconv.Atoi(value)
			switch {
			case err != nil:
				warnings = append(warnings, "размер пакетов в файле записан не числом — панель подберёт его сама")
			case mtu < MinMTU || mtu > MaxMTU:
				warnings = append(warnings, fmt.Sprintf("файл просит размер пакетов %d — это вне допустимых значений (%d…%d), панель подберёт его сама", mtu, MinMTU, MaxMTU))
			default:
				p.MTU = mtu
			}
		case section == "peer" && key == "publickey":
			if err := checkKey(value); err != nil {
				return nil, nil, fail("открытый ключ сервера в файле повреждён — запросите конфигурацию заново")
			}
			p.Peer.PublicKey = value
		case section == "peer" && key == "presharedkey":
			if err := checkKey(value); err != nil {
				return nil, nil, fail("дополнительный ключ в файле повреждён — запросите конфигурацию заново")
			}
			p.Peer.PresharedKey = value
		case section == "peer" && key == "allowedips":
			list, err := parseCIDRList(value)
			if err != nil {
				return nil, nil, fail("список адресов сервера записан неверно: %s", err)
			}
			p.Peer.AllowedIPs = list
		case section == "peer" && key == "endpoint":
			host, port, err := parseEndpoint(value)
			if err != nil {
				return nil, nil, fail("адрес сервера записан неверно: %s", err)
			}
			p.Peer.EndpointHost, p.Peer.EndpointPort = host, port
		case section == "peer" && key == "persistentkeepalive":
			if strings.EqualFold(value, "off") || value == "0" {

				p.Peer.PersistentKeepalive = 0
				seen["peer.keepalive_set"] = true
				warnings = append(warnings, "файл выключает поддержание связи — после долгого простоя (например, ночью) канал может отвечать не сразу. Если офис жалуется на первый звонок утром, запросите у поставщика конфигурацию с поддержанием связи")
				break
			}
			ka, err := strconv.Atoi(value)
			if err != nil || ka < 0 || ka > 65535 {
				warnings = append(warnings, "период поддержания связи в файле записан неверно — панель применит стандартный")
				break
			}
			p.Peer.PersistentKeepalive = ka
			seen["peer.keepalive_set"] = true
		default:
			unknown = append(unknown, strings.TrimSpace(line[:eq]))
		}
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		warnings = append(warnings, "файл содержит настройки, которых эта версия панели не знает ("+strings.Join(dedupe(unknown), ", ")+") — они пропущены, подключение это не ломает")
	}
	if peers > 1 {
		warnings = append(warnings, "в файле описано несколько серверов — панель использует первый")
	}

	if err := p.validate(); err != nil {
		return nil, nil, err
	}
	if !seen["peer.keepalive_set"] {
		p.Peer.PersistentKeepalive = DefaultKeepalive
		p.KeepaliveAssumed = true
		warnings = append(warnings, fmt.Sprintf("в файле не задан период поддержания связи — панель применит %d с, чтобы туннель не «засыпал» за оборудованием провайдера", DefaultKeepalive))
	}
	if !p.FullTunnel() {
		warnings = append(warnings, "файл направляет в защищённый канал не весь трафик, а только часть адресов — режим «весь офис через защищённый канал» с таким файлом работать не будет")
	}
	if p.hasIPv6Address() {
		warnings = append(warnings, "файл содержит адреса нового поколения (IPv6) — офису они не раздаются, на работу подключения это не влияет")
	}
	return &p, warnings, nil
}

func (p *Profile) validate() error {
	switch {
	case p.PrivateKey == "":
		return fail("в файле нет секретного ключа — это не файл подключения либо он неполный")
	case len(p.Addresses) == 0:
		return fail("в файле нет адреса подключения — запросите конфигурацию заново")
	case p.Peer.PublicKey == "":
		return fail("в файле нет открытого ключа сервера — запросите конфигурацию заново")
	case len(p.Peer.AllowedIPs) == 0:
		return fail("в файле не указано, какой трафик идёт через сервер — запросите конфигурацию заново")
	case p.Peer.EndpointHost == "":
		return fail("в файле нет адреса сервера — запросите конфигурацию заново")
	case !UsableEndpoint(net.ParseIP(p.Peer.EndpointHost)):
		return fail("адрес сервера в файле служебный (петля, широковещательный или пустой) — по такому адресу подключение не работает; запросите конфигурацию заново")
	case p.TunnelIPv4() == "":
		return fail("в файле нет адреса подключения обычного вида (IPv4) — такие конфигурации панель пока не поддерживает")
	}
	return nil
}

func (p *Profile) hasIPv6Address() bool {
	for _, a := range p.Addresses {
		if ip, _, err := net.ParseCIDR(a); err == nil && ip.To4() == nil {
			return true
		}
	}
	return false
}

func checkKey(v string) error {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("не ключ")
	}
	return nil
}

func parseCIDRList(v string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip, ipnet, err := net.ParseCIDR(part)
		if err != nil {

			if plain := net.ParseIP(part); plain != nil {
				if plain.To4() != nil {
					out = append(out, plain.String()+"/32")
				} else {
					out = append(out, plain.String()+"/128")
				}
				continue
			}
			return nil, fmt.Errorf("«%s» не похоже на адрес", part)
		}
		ones, _ := ipnet.Mask.Size()
		if ip.To4() != nil {
			out = append(out, ip.To4().String()+"/"+strconv.Itoa(ones))
		} else {
			out = append(out, ip.String()+"/"+strconv.Itoa(ones))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("список пуст")
	}
	return out, nil
}

func parseDNSList(v string) (servers, domains []string, bad string) {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			servers = append(servers, ip.String())
			continue
		}
		if vpndriver.ValidHostname(part) {
			domains = append(domains, strings.ToLower(part))
			continue
		}
		if bad == "" {
			bad = part
		}
	}
	return servers, domains, bad
}

func parseEndpoint(v string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(v)
	if err != nil {
		return "", 0, fmt.Errorf("нужен вид «адрес:порт»")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("номер порта «%s» вне допустимых значений", portStr)
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port, nil
	}
	if !vpndriver.ValidHostname(host) {
		return "", 0, fmt.Errorf("«%s» не похоже на имя или адрес сервера", host)
	}
	return strings.ToLower(host), port, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

type Render struct {
	MTU          int
	EndpointAddr string

	Mark int
}

func (p *Profile) Generate(r Render) []byte {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + p.PrivateKey + "\n")
	b.WriteString("Address = " + strings.Join(p.Addresses, ", ") + "\n")
	if r.MTU > 0 {
		b.WriteString("MTU = " + strconv.Itoa(r.MTU) + "\n")
	}
	if r.Mark > 0 {
		b.WriteString("Table = off\n")
		b.WriteString("FwMark = " + strconv.Itoa(r.Mark) + "\n")
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + p.Peer.PublicKey + "\n")
	if p.Peer.PresharedKey != "" {
		b.WriteString("PresharedKey = " + p.Peer.PresharedKey + "\n")
	}
	b.WriteString("AllowedIPs = " + strings.Join(p.Peer.AllowedIPs, ", ") + "\n")
	host := p.Peer.EndpointHost
	if r.EndpointAddr != "" {
		host = r.EndpointAddr
	}
	b.WriteString("Endpoint = " + net.JoinHostPort(host, strconv.Itoa(p.Peer.EndpointPort)) + "\n")
	if p.Peer.PersistentKeepalive > 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(p.Peer.PersistentKeepalive) + "\n")
	}
	return []byte(b.String())
}

const MaxSlug = vpndriver.MaxSlug

func Slug(name string) string { return vpndriver.Slug(name) }

func ValidSlug(s string) bool { return vpndriver.ValidSlug(s) }

func UsableEndpoint(ip net.IP) bool { return vpndriver.UsableEndpoint(ip) }
