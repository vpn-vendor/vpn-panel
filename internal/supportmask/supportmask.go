package supportmask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type Masker struct {
	key   []byte
	names *regexp.Regexp
	alias map[string]string
}

func New(key []byte) *Masker {
	return &Masker{key: append([]byte(nil), key...), alias: map[string]string{}}
}

func (m *Masker) tag(kind, value string, n int) string {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:n]
}

func (m *Masker) Device(mac string) string {
	return "устройство-" + m.tag("mac", normMAC(mac), 6)
}

func (m *Masker) Profile(slug string) string {
	return "подключение-" + m.tag("profile", slug, 4)
}

func normMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
}

const minName = 3

func (m *Masker) Known(name, mac string) {
	name = strings.TrimSpace(name)
	if len([]rune(name)) < minName {
		return
	}
	if mac != "" {
		m.alias[strings.ToLower(name)] = m.Device(mac)
	} else {
		m.alias[strings.ToLower(name)] = "имя-" + m.tag("name", strings.ToLower(name), 6)
	}
	m.names = nil
}

func (m *Masker) Alias(value, replacement string) {
	if len([]rune(value)) < minName {
		return
	}
	m.alias[strings.ToLower(value)] = replacement
	m.names = nil
}

func (m *Masker) compile() {
	if m.names != nil || len(m.alias) == 0 {
		return
	}
	keys := make([]string, 0, len(m.alias))
	for k := range m.alias {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for i, k := range keys {
		keys[i] = regexp.QuoteMeta(k)
	}
	m.names = regexp.MustCompile("(?i)" + strings.Join(keys, "|"))
}

var (
	macRx = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)

	ip4Rx = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ip6Rx = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,7}(?::?[0-9a-f]{1,4}){0,6}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}`)

	keyRx = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)

	hexRx = regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`)
	pemRx = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`)
)

const Hidden = "<скрыто>"

func public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		b := a.As4()

		if b[0] == 100 && b[1]&0xc0 == 64 || b == [4]byte{255, 255, 255, 255} || b[0] == 0 {
			return false
		}
	}
	return true
}

func (m *Masker) Addr(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || !public(a) {
		return s
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return itoa(b[0]) + "." + itoa(b[1]) + ".x.x~" + m.tag("ip", a.String(), 4)
	}
	b := a.As16()
	return hex.EncodeToString(b[0:2]) + ":" + hex.EncodeToString(b[2:4]) + ":x~" + m.tag("ip", a.String(), 4)
}

func itoa(b byte) string {
	const digits = "0123456789"
	if b < 10 {
		return digits[b : b+1]
	}
	if b < 100 {
		return string([]byte{digits[b/10], digits[b%10]})
	}
	return string([]byte{digits[b/100], digits[b/10%10], digits[b%10]})
}

func (m *Masker) Line(s string) string {
	if pemRx.MatchString(s) {
		return Hidden
	}
	s = keyRx.ReplaceAllString(s, Hidden)
	s = macRx.ReplaceAllStringFunc(s, m.Device)
	s = hexRx.ReplaceAllStringFunc(s, func(v string) string { return "<код~" + m.tag("hex", strings.ToLower(v), 4) + ">" })
	s = ip4Rx.ReplaceAllStringFunc(s, m.Addr)
	s = ip6Rx.ReplaceAllStringFunc(s, m.Addr)
	m.compile()
	if m.names != nil {
		s = m.names.ReplaceAllStringFunc(s, func(v string) string { return m.alias[strings.ToLower(v)] })
	}
	return s
}
