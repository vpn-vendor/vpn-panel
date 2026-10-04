package vpnproto

import (
	"fmt"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/ovpngen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

var modules = []vpndriver.Descriptor{wggen.Descriptor, ovpngen.Descriptor}

const legacyEmpty = wggen.ID

func All() []vpndriver.Descriptor { return append([]vpndriver.Descriptor(nil), modules...) }

func Lookup(p vpndriver.Protocol) (vpndriver.Descriptor, bool) {
	for _, d := range modules {
		if d.ID == p {
			return d, true
		}
	}
	return vpndriver.Descriptor{}, false
}

func Known(p vpndriver.Protocol) bool {
	_, ok := Lookup(p)
	return ok
}

func Parse(s string) vpndriver.Protocol {
	return vpndriver.Protocol(strings.ToLower(strings.TrimSpace(s)))
}

func Stored(s string) vpndriver.Protocol {
	if strings.TrimSpace(s) == "" {
		return legacyEmpty
	}
	return Parse(s)
}

func Iface(p vpndriver.Protocol) string {
	d, _ := Lookup(p)
	return d.Iface
}

func Passport(p vpndriver.Protocol, transport string) (vpndriver.Passport, bool) {
	d, ok := Lookup(p)
	if !ok {
		return vpndriver.Passport{}, false
	}
	return d.Passport(transport), true
}

func Detect(text string) (vpndriver.Descriptor, error) {
	if len(text) > vpndriver.MaxConfigBytes {
		return vpndriver.Descriptor{}, fmt.Errorf("файл слишком большой для конфигурации подключения — проверьте, что выбран нужный файл")
	}
	if msg := vpndriver.ShapeError(text); msg != "" {
		return vpndriver.Descriptor{}, fmt.Errorf("%s", msg)
	}
	hit := make([]bool, len(modules))
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		lower := strings.ToLower(line)
		for i, d := range modules {
			hit[i] = hit[i] || d.Marks(lower)
		}
	}
	var found []vpndriver.Descriptor
	for i, d := range modules {
		if hit[i] {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		var hints []string
		for _, d := range modules {
			hints = append(hints, d.Hint)
		}
		return vpndriver.Descriptor{}, fmt.Errorf("файл не похож на файл подключения: нужен файл %s", strings.Join(hints, " или "))
	}
	var labels []string
	for _, d := range found {
		labels = append(labels, d.Label)
	}
	return vpndriver.Descriptor{}, fmt.Errorf("файл похож сразу на %s — выберите файл одного подключения, который прислал поставщик",
		strings.Join(labels, " и "))
}

func IDs() string {
	var ids []string
	for _, d := range modules {
		ids = append(ids, string(d.ID))
	}
	return strings.Join(ids, " или ")
}

func FileExts() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range modules {
		for _, e := range d.FileExts {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}

func Keywords() []string {
	var out []string
	for _, d := range modules {
		out = append(out, d.Keywords...)
	}
	return out
}

func Ifaces() []string {
	var out []string
	for _, d := range modules {
		out = append(out, d.Iface)
	}
	return out
}

func Packages() []string {
	var out []string
	for _, d := range modules {
		out = append(out, d.Packages...)
	}
	return out
}
