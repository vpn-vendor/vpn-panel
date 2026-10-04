package vpndriver

import (
	"net"

	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Truth uint8

const (
	Unknown Truth = iota
	No
	Yes
)

func (t Truth) Known() bool { return t != Unknown }
func (t Truth) IsYes() bool { return t == Yes }
func (t Truth) IsNo() bool  { return t == No }

func TruthOf(b bool) Truth {
	if b {
		return Yes
	}
	return No
}

func (t Truth) String() string {
	switch t {
	case Yes:
		return "yes"
	case No:
		return "no"
	default:
		return "unknown"
	}
}

func (t Truth) MarshalText() ([]byte, error) { return []byte(t.String()), nil }
func (t *Truth) UnmarshalText(b []byte) error {
	switch string(b) {
	case "yes":
		*t = Yes
	case "no":
		*t = No
	default:
		*t = Unknown
	}
	return nil
}

type Protocol string

type Descriptor struct {
	ID    Protocol
	Label string

	Iface string

	Hint string

	FileExts []string

	Transports []string

	Packages []string

	Keywords []string

	Marks func(line string) bool

	Passport func(transport string) Passport

	CheckMeta func(m Meta) fielderr.List
}

func (d Descriptor) Transport(t string) string {
	if t == "" && len(d.Transports) > 0 {
		return d.Transports[0]
	}
	return t
}

const (
	TransportUDP = "udp"
	TransportTCP = "tcp"
)

const (
	LivenessHandshake = "handshake"
	LivenessProcess   = "process"
)

const Mark = 51820

type Passport struct {
	Protocol  Protocol `json:"protocol"`
	Transport string   `json:"transport"`

	KernelDataPlane bool `json:"kernel_data_plane"`

	UsesAES bool `json:"uses_aes"`

	SetsMark bool `json:"sets_mark"`

	ManagesRoutes bool `json:"manages_routes"`

	ServerPushes bool `json:"server_pushes"`

	AddressAtImport bool `json:"address_at_import"`

	ProbeCandidates []string `json:"probe_candidates"`

	Liveness string `json:"liveness"`

	ProgressPeriod time.Duration `json:"progress_period"`
	SelfHealBudget time.Duration `json:"self_heal_budget"`

	CanPause bool `json:"can_pause"`

	ClockSensitive bool `json:"clock_sensitive"`

	OverheadIPv4 int `json:"overhead_ipv4"`
	OverheadIPv6 int `json:"overhead_ipv6"`
}

func (p Passport) StaleAfter() time.Duration { return p.ProgressPeriod + p.SelfHealBudget }

func VoiceFit(transport string) bool { return transport != TransportTCP }

type Meta struct {
	Protocol     Protocol `json:"protocol"`
	Transport    string   `json:"transport"`
	Addresses    []string `json:"addresses"`
	PeerKey      string   `json:"peer_key"`
	AllowedIPs   []string `json:"allowed_ips"`
	EndpointHost string   `json:"endpoint_host"`
	EndpointPort int      `json:"endpoint_port"`
	ConfigDNS    []string `json:"config_dns,omitempty"`
	ConfigMTU    int      `json:"config_mtu,omitempty"`
	Keepalive    int      `json:"keepalive"`
	FullTunnel   bool     `json:"full_tunnel"`

	VoiceFit bool `json:"voice_fit"`
}

func ShapeError(text string) string {
	if strings.TrimSpace(text) == "" {
		return "файл пуст — выберите файл подключения, который прислал поставщик"
	}
	if !utf8.ValidString(text) {
		return "это не файл подключения: внутри не текст. Выберите файл подключения, который прислал поставщик"
	}
	control := 0
	for _, r := range text {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			control++
		}
	}

	if control > 2 {
		return "это не файл подключения: внутри не текст. Выберите файл подключения, который прислал поставщик"
	}
	return ""
}

const MaxConfigBytes = 64 * 1024

const (
	MinMTU = 1280
	MaxMTU = 1500
)

const (
	ProbeLow    = MinMTU - 28
	ProbeHigh   = MaxMTU - 28
	ProbeHeader = 28
)

func NextProbe(low, high int) int {
	if high-low <= 1 {
		return 0
	}
	return low + (high-low)/2
}

func TunnelMTU(pathMTU, overhead int) int {
	mtu := pathMTU - overhead
	if mtu < MinMTU {
		return MinMTU
	}
	if mtu > MaxMTU {
		return MaxMTU
	}
	return mtu
}

func UsableEndpoint(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() &&
		!ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.Equal(net.IPv4bcast)
}

var slugDrop = regexp.MustCompile(`[^a-z0-9]+`)

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "h", 'ц': "c", 'ч': "ch", 'ш': "sh", 'щ': "sch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

const MaxSlug = 24

func Slug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if t, ok := translit[r]; ok {
			b.WriteString(t)
			continue
		}
		b.WriteRune(r)
	}
	s := strings.Trim(slugDrop.ReplaceAllString(b.String(), "-"), "-")
	if len(s) > MaxSlug {
		s = strings.Trim(s[:MaxSlug], "-")
	}
	if s == "" {
		return "profil"
	}
	return s
}

func UniqueSlug(base string, taken func(string) bool) string {
	if !taken(base) {
		return base
	}
	for i := 2; i < 1000; i++ {
		if s := withSuffix(base, "-"+strconv.Itoa(i)); !taken(s) {
			return s
		}
	}
	return withSuffix(base, "-x")
}

func withSuffix(base, suffix string) string {
	if room := MaxSlug - len(suffix); len(base) > room {
		base = strings.TrimRight(base[:room], "-")
	}
	if base == "" {
		base = "p"
	}
	return base + suffix
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func ValidHostname(s string) bool { return len(s) <= 253 && hostRe.MatchString(s) }

func ValidHost(s string) bool { return net.ParseIP(s) != nil || ValidHostname(s) }

func ValidSlug(s string) bool { return slugRe.MatchString(s) }
