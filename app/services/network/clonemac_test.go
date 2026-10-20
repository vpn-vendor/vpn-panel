package network

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func TestCloneConflict(t *testing.T) {
	st := &netstatus.Status{Interfaces: []netstatus.Interface{
		{Name: "ens2", MAC: "52:54:00:00:00:02"}, {Name: "ens3", MAC: "52:54:00:00:00:03"}}}
	if CloneConflict("00:1a:2b:3c:4d:5e", "ens2", st, nil) != "" {
		t.Error("чужой адрес без соседей — можно")
	}
	if !strings.Contains(CloneConflict("52:54:00:00:00:03", "ens2", st, nil), "ens3") {
		t.Error("адрес другой карты шлюза — нельзя")
	}
	neigh := []netstatus.Neighbor{{IP: "10.0.0.1", Dev: "ens2", MAC: "00:1a:2b:3c:4d:5e"}}
	if !strings.Contains(CloneConflict("00:1a:2b:3c:4d:5e", "ens2", st, neigh), "старый роутер") {
		t.Error("адрес отвечает в сети — нельзя")
	}
}

func wanSection() Section {
	return Section{ConfirmTimeoutSec: 120, Interfaces: []SectionInterface{
		{Name: "ens2", MAC: "52:54:00:00:00:02", Role: netplangen.RoleWAN, IPv4Method: netplangen.MethodDHCP, WANMetric: 100},
		{Name: "ens3", MAC: "52:54:00:00:00:03", Role: netplangen.RoleLAN, IPv4Method: netplangen.MethodStatic, IPv4CIDR: "192.168.11.1/24"},
	}}
}

func TestSetRoleCloneMAC(t *testing.T) {
	s := wanSection()
	wan := RoleInput{Name: "ens2", MAC: "52:54:00:00:00:02", Role: netplangen.RoleWAN, WANMethod: netplangen.MethodDHCP}
	in := wan
	in.CloneMAC, in.CloneSet = "00-1A-2B-3C-4D-5E", true
	if err := s.SetRole(in); err != nil {
		t.Fatal(err)
	}
	if s.Interfaces[0].CloneMAC != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("приведение: %q", s.Interfaces[0].CloneMAC)
	}
	if errs := ValidateSection(s); len(errs) != 0 {
		t.Fatalf("раздел с подменой: %v", errs)
	}
	if p := s.Plan(); p.Interfaces[0].MAC != "00:1a:2b:3c:4d:5e" {
		t.Errorf("подмена не дошла до плана: %+v", p.Interfaces[0])
	}
	_ = s.SetRole(wan)
	if s.Interfaces[0].CloneMAC == "" {
		t.Error("форма без поля стёрла подмену")
	}
	in.CloneMAC = ""
	_ = s.SetRole(in)
	if s.Interfaces[0].CloneMAC != "" {
		t.Error("пустое поле — родной адрес")
	}
	in.CloneMAC = "aabb"
	if s.SetRole(in) == nil {
		t.Error("короткий адрес — ошибка человеку")
	}
}

func TestValidateSectionCloneMAC(t *testing.T) {
	s := wanSection()
	s.Interfaces[0].CloneMAC = "52:54:00:00:00:03"
	if errs := ValidateSection(s); len(errs) == 0 {
		t.Error("адрес другой карты шлюза — ошибка")
	}
	s.Interfaces[0].CloneMAC = "52:54:00:00:00:02"
	if errs := ValidateSection(s); len(errs) == 0 {
		t.Error("родной адрес как подмена — ошибка")
	}
	s = wanSection()
	s.Interfaces[1].CloneMAC = "00:1a:2b:3c:4d:5e"
	if errs := ValidateSection(s); len(errs) == 0 {
		t.Error("подмена у LAN — ошибка")
	}
}
