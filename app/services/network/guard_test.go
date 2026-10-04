package network

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func TestGuardNeededOnlyWhenAdminPathChanges(t *testing.T) {
	lan := netplangen.PlanInterface{Name: "ens4", Role: netplangen.RoleLAN,
		Method: netplangen.MethodStatic, CIDR: "192.168.11.1/24"}
	st := &netstatus.Status{Interfaces: []netstatus.Interface{
		{Name: "ens3", Addresses: []string{"192.168.100.190/24"}},
		{Name: "ens4", Addresses: []string{"192.168.11.1/24"}},
	}}
	admin := "192.168.11.50"
	s := New()

	cases := []struct {
		name string
		plan netplangen.Plan
		want bool
	}{
		{

			name: "смена метода WAN окна не требует",
			plan: netplangen.Plan{Interfaces: []netplangen.PlanInterface{lan,
				{Name: "ens3", Role: netplangen.RoleWAN, Method: netplangen.MethodPPPoE, Username: "u"}}},
			want: false,
		},
		{
			name: "смена адреса его же сети требует окна",
			plan: netplangen.Plan{Interfaces: []netplangen.PlanInterface{
				{Name: "ens4", Role: netplangen.RoleLAN, Method: netplangen.MethodStatic, CIDR: "192.168.22.1/24"},
				{Name: "ens3", Role: netplangen.RoleWAN, Method: netplangen.MethodDHCP}}},
			want: true,
		},
		{
			name: "его карта уходит из плана — окно нужно",
			plan: netplangen.Plan{Interfaces: []netplangen.PlanInterface{
				{Name: "ens3", Role: netplangen.RoleWAN, Method: netplangen.MethodDHCP}}},
			want: true,
		},
		{
			name: "его карта меняет роль на WAN — окно нужно",
			plan: netplangen.Plan{Interfaces: []netplangen.PlanInterface{
				{Name: "ens4", Role: netplangen.RoleWAN, Method: netplangen.MethodDHCP}}},
			want: true,
		},
	}
	for _, c := range cases {
		if got := s.GuardNeeded(admin, c.plan, st); got != c.want {
			t.Errorf("%s: окно=%v, ожидалось %v", c.name, got, c.want)
		}
	}

	loop := netplangen.Plan{Interfaces: []netplangen.PlanInterface{
		{Name: "ens4", Role: netplangen.RoleWAN, Method: netplangen.MethodDHCP}}}
	if s.GuardNeeded("127.0.0.1", loop, st) {
		t.Error("с loopback окно не требуется")
	}
}
