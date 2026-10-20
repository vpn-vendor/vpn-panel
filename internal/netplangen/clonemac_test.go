package netplangen

import (
	"strings"
	"testing"
)

func TestValidCloneMAC(t *testing.T) {
	for mac, ok := range map[string]bool{
		"00:1a:2b:3c:4d:5e": true, "02:00:00:00:00:01": true,
		"01:00:5e:00:00:01": false,
		"00:00:00:00:00:00": false, "ff:ff:ff:ff:ff:ff": false,
		"00-1a-2b-3c-4d-5e": false, "00:1A:2B:3C:4D:5E": false, "00:1a:2b:3c:4d": false,
	} {
		if ValidCloneMAC(mac) != ok {
			t.Errorf("%s: ждали %v", mac, ok)
		}
	}
}

func TestCloneMACInNetplan(t *testing.T) {
	p := Plan{Interfaces: []PlanInterface{
		{Name: "ens2", Role: RoleWAN, Method: MethodDHCP, MAC: "00:1a:2b:3c:4d:5e"},
		{Name: "ens3", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
	}}
	if err := p.Validate(nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{RendererNetworkd, RendererNM} {
		y := string(p.Generate(r, nil))
		if strings.Count(y, "macaddress:") != 1 || !strings.Contains(y, "    ens2:\n      macaddress: \"00:1a:2b:3c:4d:5e\"\n") {
			t.Errorf("%s: адрес не у карты WAN:\n%s", r, y)
		}
	}
	p.Interfaces[0].VLAN = 100
	if y := string(p.Generate(RendererNetworkd, nil)); !strings.Contains(y, "    ens2:\n      macaddress:") {
		t.Errorf("с тегом адрес — у базовой карты:\n%s", y)
	}
	lan := Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24", MAC: "00:1a:2b:3c:4d:5e"}}}
	if lan.Validate(nil) == nil {
		t.Error("у LAN подмена запрещена")
	}
	bad := Plan{Interfaces: []PlanInterface{{Name: "ens2", Role: RoleWAN, Method: MethodDHCP, MAC: "01:00:5e:00:00:01"}}}
	if bad.Validate(nil) == nil {
		t.Error("групповой адрес не годится")
	}
}
