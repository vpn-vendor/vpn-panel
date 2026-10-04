package vpnproto_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/ovpngen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

var update = flag.Bool("update", false, "переписать эталон")

const (
	wgPriv = "6HrAtQNTBhaOAxo2rEyOEqYnLXQ5U8DdAxIQyfaFvV4="
	wgPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	wgPSK  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
)

func ovpnBlocks() string {
	key := strings.ReplaceAll("-----BEGIN TESTING KEY-----\nMIIBKE\n-----END TESTING KEY-----", "TESTING KEY", "PRIVATE KEY")
	return "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBCA\n-----END CERTIFICATE-----\n</ca>\n" +
		"<cert>\n-----BEGIN CERTIFICATE-----\nMIIBCE\n-----END CERTIFICATE-----\n</cert>\n" +
		"<key>\n" + key + "\n</key>\n"
}

func samples() map[string]string {
	wg := "[Interface]\nPrivateKey = " + wgPriv + "\nAddress = 10.66.66.2/32\nDNS = 10.66.66.1\nMTU = 1420\n\n" +
		"[Peer]\nPublicKey = " + wgPub + "\nPresharedKey = " + wgPSK + "\nAllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = vpn.example.net:51820\nPersistentKeepalive = 25\n"
	return map[string]string{
		"wg-vendor":      wg,
		"wg-ipv6":        strings.Replace(wg, "Address = 10.66.66.2/32", "Address = 10.66.66.2/32, fd00::2/128", 1),
		"wg-split":       strings.Replace(wg, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8", 1),
		"wg-no-endpoint": strings.Replace(wg, "Endpoint = vpn.example.net:51820\n", "", 1),
		"wg-bad-key":     strings.Replace(wg, wgPub, "not-a-key", 1),
		"ovpn-vendor": "client\ndev tun\nproto udp\nremote vpn.example.net 1194\nnobind\nremote-cert-tls server\n" +
			"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nverb 3\n" + ovpnBlocks(),
		"ovpn-tcp":    "client\ndev tun\nproto tcp-client\nremote 192.0.2.7 443\nremote-cert-tls server\n" + ovpnBlocks(),
		"ovpn-script": "client\ndev tun\nremote vpn.example.net 1194\nscript-security 2\nup /tmp/x.sh\n" + ovpnBlocks(),
		"both":        wg + "\nremote vpn.example.net 1194\n" + ovpnBlocks(),
		"empty":       "",
		"garbage":     "это не файл подключения\n\x00\x01",
	}
}

type parsed struct {
	Protocol  string          `json:"protocol,omitempty"`
	DetectErr string          `json:"detect_err,omitempty"`
	Shape     string          `json:"shape,omitempty"`
	Meta      *vpndriver.Meta `json:"meta,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
	ParseErr  string          `json:"parse_err,omitempty"`
	Generated string          `json:"generated,omitempty"`
	Library   string          `json:"library,omitempty"`
}

func masked(s string) string { return strings.ReplaceAll(s, "PRIVATE KEY", "TESTING KEY") }

func characterize(text string) parsed {
	out := characterizeRaw(text)
	out.Generated, out.Library = masked(out.Generated), masked(out.Library)
	return out
}

func characterizeRaw(text string) parsed {
	var out parsed
	out.Shape = vpndriver.ShapeError(text)
	d, err := vpnproto.Detect(text)
	if err != nil {
		out.DetectErr = err.Error()
		return out
	}
	out.Protocol = string(d.ID)
	switch d.ID {
	case wggen.ID:
		prof, warn, err := wggen.Parse(text)
		out.Warnings = warn
		if err != nil {
			out.ParseErr = err.Error()
			return out
		}
		m := prof.Meta()
		out.Meta = &m
		out.Generated = string(prof.Generate(wggen.Render{MTU: 1420, EndpointAddr: "192.0.2.10", Mark: vpndriver.Mark}))
	case ovpngen.ID:
		prof, warn, err := ovpngen.Parse(text)
		out.Warnings = warn
		if err != nil {
			out.ParseErr = err.Error()
			return out
		}
		m := prof.Meta()
		out.Meta = &m
		out.Library = string(prof.Library())
		out.Generated = string(prof.Generate(ovpngen.Render{Iface: d.Iface, Mark: vpndriver.Mark, MTU: 1400,
			Remotes: []ovpngen.Remote{{Host: "192.0.2.10", Port: 1194, Proto: "udp"}}, Management: "/run/management.sock"}))
	}
	return out
}

type names struct {
	Normalized string `json:"normalized"`
	Stored     string `json:"stored"`
	Valid      bool   `json:"valid"`
	Iface      string `json:"iface"`
}

type golden struct {
	Files     map[string]parsed             `json:"files"`
	Names     map[string]names              `json:"names"`
	Passports map[string]vpndriver.Passport `json:"passports"`
}

func current() golden {
	g := golden{Files: map[string]parsed{}, Names: map[string]names{}, Passports: map[string]vpndriver.Passport{}}
	for name, text := range samples() {
		g.Files[name] = characterize(text)
	}
	for _, s := range []string{"", "wireguard", "openvpn", " OpenVPN ", "WIREGUARD", "ipsec", "open vpn"} {
		p := vpnproto.Parse(s)
		g.Names["«"+s+"»"] = names{Normalized: string(p), Stored: string(vpnproto.Stored(s)), Valid: vpnproto.Known(p), Iface: vpnproto.Iface(p)}
	}
	for _, d := range vpnproto.All() {
		for _, tr := range []string{vpndriver.TransportUDP, vpndriver.TransportTCP, ""} {
			g.Passports[string(d.ID)+"/"+tr], _ = vpnproto.Passport(d.ID, tr)
		}
	}
	return g
}

func TestBehaviourUnchanged(t *testing.T) {
	got, err := json.MarshalIndent(current(), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "protocols.golden.json")
	if *update {
		if err := os.WriteFile(path, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		t.Fatalf("эталона нет — снимите его: go test ./internal/vpnproto/ -run TestBehaviourUnchanged -update: %v", err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("поведение протоколов изменилось:\n%s", firstDiff(string(want), string(got)))
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return "строка " + itoa(i+1) + ":\n  было:  " + al[i] + "\n  стало: " + bl[i]
		}
	}
	return "разная длина эталона"
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
