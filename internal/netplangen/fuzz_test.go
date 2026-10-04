package netplangen

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func FuzzGenerateOnlyPlanned(f *testing.F) {
	f.Add("ens3", RoleWAN, MethodStatic, "203.0.113.45/24", "203.0.113.1", "1.1.1.1", "", 0,
		"ens4", RoleLAN, MethodStatic, "192.168.11.1/24", "", "", false)
	f.Add("ens3", RoleWAN, MethodDHCP, "", "", "", "", 100,
		"ens4", RoleLAN, MethodStatic, "192.168.11.1/24", "", "", true)
	f.Add("ens3", RoleWAN, MethodPPPoE, "", "", "", "user", 7,
		"ens4", RoleLAN, MethodStatic, "10.0.0.1/8", "", "", false)

	f.Add("ens3", RoleWAN, MethodStatic, "203.0.113.45/24", "203.0.113.1", "1.1.1.1]\n    ens9:\n      dhcp4: true", "", 0,
		"ens4", RoleLAN, MethodStatic, "192.168.11.1/24", "", "", false)
	f.Fuzz(func(t *testing.T, n1, r1, m1, c1, g1, d1, u1 string, v1 int,
		n2, r2, m2, c2, g2, d2 string, ipv6 bool) {
		p := &Plan{IPv6: ipv6, Interfaces: []PlanInterface{
			{Name: n1, Role: r1, Method: m1, CIDR: c1, Gateway: g1, DNS: list(d1), Username: u1, VLAN: v1},
			{Name: n2, Role: r2, Method: m2, CIDR: c2, Gateway: g2, DNS: list(d2)},
		}}
		if p.Validate(nil) != nil {
			return
		}
		for _, renderer := range []string{RendererNetworkd, RendererNM} {
			if err := onlyPlanned(p, p.Generate(renderer, nil)); err != nil {
				t.Fatalf("%s: %v\nплан: %+v", renderer, err, p.Interfaces)
			}
		}
	})
}

func list(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type definition struct {
	DHCP4          *bool          `yaml:"dhcp4"`
	DHCP4Overrides map[string]any `yaml:"dhcp4-overrides"`
	Addresses      []string       `yaml:"addresses"`
	Routes         []route        `yaml:"routes"`
	Nameservers    *struct {
		Addresses []string `yaml:"addresses"`
	} `yaml:"nameservers"`
	DHCP6          *bool          `yaml:"dhcp6"`
	AcceptRA       *bool          `yaml:"accept-ra"`
	LinkLocal      []string       `yaml:"link-local"`
	NetworkManager map[string]any `yaml:"networkmanager"`
	ID             *int           `yaml:"id"`
	Link           *string        `yaml:"link"`
}

type route struct {
	To     string `yaml:"to"`
	Via    string `yaml:"via"`
	Metric int    `yaml:"metric"`
}

func onlyPlanned(p *Plan, doc []byte) error {
	var y struct {
		Network struct {
			Version   int                   `yaml:"version"`
			Renderer  string                `yaml:"renderer"`
			Ethernets map[string]definition `yaml:"ethernets"`
			VLANs     map[string]definition `yaml:"vlans"`
		} `yaml:"network"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(doc)))
	dec.KnownFields(true)
	if err := dec.Decode(&y); err != nil {
		return fmt.Errorf("YAML не разбирается строго: %v\n%s", err, doc)
	}
	want := map[string]bool{}
	for _, i := range p.Interfaces {
		want[i.Name] = true
		if i.VLAN > 0 {
			want[LinkIface(i.Name, i.VLAN)] = true
		}
	}
	got := map[string]bool{}
	for k := range y.Network.Ethernets {
		got[k] = true
	}
	for k := range y.Network.VLANs {
		got[k] = true
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("определения %v, в плане %v\n%s", keys(got), keys(want), doc)
	}
	for _, i := range p.Interfaces {
		l3 := y.Network.Ethernets[i.Name]
		if i.VLAN > 0 {
			l3 = y.Network.VLANs[LinkIface(i.Name, i.VLAN)]
			if l3.ID == nil || *l3.ID != i.VLAN || l3.Link == nil || *l3.Link != i.Name {
				return fmt.Errorf("%s: тег или ссылка не из плана\n%s", i.Name, doc)
			}
			if b := y.Network.Ethernets[i.Name]; b.Addresses != nil || b.Routes != nil || b.Nameservers != nil {
				return fmt.Errorf("%s: у карты под тегом есть адрес, маршрут или серверы имён\n%s", i.Name, doc)
			}
		}
		if err := sameL3(i, l3); err != nil {
			return fmt.Errorf("%s: %v\n%s", i.Name, err, doc)
		}
	}
	return nil
}

func sameL3(i PlanInterface, d definition) error {
	switch methodOf(i) {
	case MethodStatic:
		if !reflect.DeepEqual(d.Addresses, []string{i.CIDR}) {
			return fmt.Errorf("адреса %q, в плане %q", d.Addresses, i.CIDR)
		}
		if i.Gateway == "" {
			if d.Routes != nil || d.Nameservers != nil {
				return fmt.Errorf("маршрут или серверы имён без шлюза в плане")
			}
			return nil
		}
		if len(d.Routes) != 1 || d.Routes[0].Via != i.Gateway || d.Routes[0].To != "default" {
			return fmt.Errorf("маршрут %+v, в плане шлюз %q", d.Routes, i.Gateway)
		}
		dns := i.DNS
		if len(dns) == 0 {
			dns = WANNameservers
		}
		if d.Nameservers == nil || !reflect.DeepEqual(d.Nameservers.Addresses, dns) {
			return fmt.Errorf("серверы имён %+v, в плане %q", d.Nameservers, dns)
		}
	case MethodDHCP:
		if d.Addresses != nil || d.Routes != nil {
			return fmt.Errorf("у DHCP адреса или маршруты из плана")
		}
	default:
		if d.Addresses != nil || d.Routes != nil || d.Nameservers != nil {
			return fmt.Errorf("у карты без адреса есть адреса, маршруты или серверы имён")
		}
	}
	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
