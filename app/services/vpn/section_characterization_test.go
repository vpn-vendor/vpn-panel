package vpn

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateSection = flag.Bool("update-section", false, "переписать эталон проверки раздела")

func sectionRows() map[string]SectionProfile {
	wg := SectionProfile{Name: "Офис", Slug: "office", Protocol: "wireguard", Transport: "udp",
		EndpointHost: "vpn.example.net", EndpointPort: 51820, PeerKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		Addresses: "10.66.66.2/32", AllowedIPs: "0.0.0.0/0", ConfigDNS: "10.66.66.1", ConfigMTU: 1420, Keepalive: 25}
	ov := SectionProfile{Name: "Офис", Slug: "office", Protocol: "openvpn", Transport: "udp",
		EndpointHost: "vpn.example.net", EndpointPort: 1194}
	rows := map[string]SectionProfile{"wg-ok": wg, "ovpn-ok": ov}
	put := func(name string, base SectionProfile, edit func(*SectionProfile)) {
		p := base
		edit(&p)
		rows[name] = p
	}
	put("wg-tcp", wg, func(p *SectionProfile) { p.Transport = "tcp" })
	put("wg-bad-key", wg, func(p *SectionProfile) { p.PeerKey = "короткий" })
	put("wg-no-addresses", wg, func(p *SectionProfile) { p.Addresses, p.AllowedIPs = "", "" })
	put("ovpn-tcp", ov, func(p *SectionProfile) { p.Transport = "tcp" })
	put("ovpn-with-key", ov, func(p *SectionProfile) { p.PeerKey, p.Addresses = wg.PeerKey, "10.0.0.2/32" })
	put("empty-protocol", wg, func(p *SectionProfile) { p.Protocol = "" })
	put("unknown-protocol", wg, func(p *SectionProfile) { p.Protocol = "ipsec" })
	put("bad-transport", ov, func(p *SectionProfile) { p.Transport = "quic" })
	put("bad-port", ov, func(p *SectionProfile) { p.EndpointPort = 70000 })
	put("unset-port", ov, func(p *SectionProfile) { p.EndpointPort = 0 })
	put("bad-mtu", wg, func(p *SectionProfile) { p.ConfigMTU = 100 })
	return rows
}

func TestSectionValidationUnchanged(t *testing.T) {
	out := map[string][]string{}
	for name, row := range sectionRows() {
		var msgs []string
		for _, e := range validateProfile(row) {
			msgs = append(msgs, e.Error())
		}
		sort.Strings(msgs)
		out[name] = msgs
	}
	got, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "section-profiles.golden.json")
	if *updateSection {
		if err := os.WriteFile(path, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		t.Fatalf("эталона нет — снимите его с -update-section: %v", err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("проверка строк профилей изменилась:\nбыло:\n%s\nстало:\n%s", want, got)
	}
}
