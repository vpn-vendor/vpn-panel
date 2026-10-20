package takeover

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

type npMatch struct {
	Name       string `yaml:"name"`
	MACAddress string `yaml:"macaddress"`
	Driver     any    `yaml:"driver"`
}

type npDef struct {
	Match      *npMatch `yaml:"match"`
	SetName    string   `yaml:"set-name"`
	Interfaces []string `yaml:"interfaces"`
	Link       string   `yaml:"link"`
}

type npDoc struct {
	Network struct {
		Ethernets map[string]npDef `yaml:"ethernets"`
		Wifis     map[string]npDef `yaml:"wifis"`
		Bonds     map[string]npDef `yaml:"bonds"`
		Bridges   map[string]npDef `yaml:"bridges"`
		Vlans     map[string]npDef `yaml:"vlans"`
	} `yaml:"network"`
}

type netplanFile struct {
	name string
	doc  npDoc
}

func (b *builder) netplanFiles() []netplanFile {
	ents, _ := os.ReadDir(b.path(legacyvpn.NetplanDir))
	var out []netplanFile
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".yaml") || n == b.env.OwnNetplan {
			continue
		}
		if n == filepath.Base(legacyvpn.ScriptNetplan) && b.has("legacy.netplan") {
			continue
		}
		p := legacyvpn.NetplanDir + "/" + n
		data, ok := b.read(p)
		if !ok || !b.isFile(p) {
			continue
		}
		var doc npDoc

		var te *yaml.TypeError
		if err := yaml.Unmarshal(data, &doc); err != nil && !errors.As(err, &te) {
			continue
		}
		out = append(out, netplanFile{name: n, doc: doc})
	}
	slices.SortFunc(out, func(x, y netplanFile) int { return strings.Compare(x.name, y.name) })
	return out
}

func (f netplanFile) describes(cards, all []string, macs map[string]string) (described, others []string) {
	hit := map[string]bool{}
	other := func(id string) {
		if !slices.Contains(others, id) {
			others = append(others, id)
		}
	}
	visit := func(defs map[string]npDef, virtual bool, card func(id string, d npDef, c string) bool) {
		for id, d := range defs {
			matched := false
			for _, c := range cards {
				if card(id, d, c) {
					hit[c], matched = true, true
				}
			}
			if !matched || (virtual && !slices.Contains(cards, id)) {
				other(id)
			}
		}
	}
	phys := func(id string, d npDef, c string) bool { return physMatches(id, d, c, macs[c]) }
	visit(f.doc.Network.Ethernets, false, phys)
	visit(f.doc.Network.Wifis, false, phys)

	for _, defs := range []map[string]npDef{f.doc.Network.Ethernets, f.doc.Network.Wifis} {
		for id, d := range defs {
			for _, c := range all {
				if !slices.Contains(cards, c) && phys(id, d, c) {
					other(id)
				}
			}
		}
	}

	member := func(id string, d npDef, c string) bool { return id == c || slices.Contains(d.Interfaces, c) }
	visit(f.doc.Network.Bonds, true, member)
	visit(f.doc.Network.Bridges, true, member)
	visit(f.doc.Network.Vlans, true, func(id string, d npDef, c string) bool { return id == c || d.Link == c })
	for _, c := range cards {
		if hit[c] {
			described = append(described, c)
		}
	}
	slices.Sort(others)
	return described, others
}

func physMatches(id string, d npDef, c, mac string) bool {
	if d.SetName != "" && d.SetName == c {
		return true
	}
	if d.Match == nil {
		return id == c
	}
	if d.Match.Name != "" {
		if ok, err := filepath.Match(d.Match.Name, c); err != nil || !ok {
			return false
		}
	}
	if d.Match.MACAddress != "" && mac != "" && !strings.EqualFold(d.Match.MACAddress, mac) {
		return false
	}
	return true
}
