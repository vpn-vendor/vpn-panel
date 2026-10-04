package bindset

import (
	"net"
	"reflect"
	"testing"
)

func ifaces() []Interface {
	return []Interface{
		{Name: "ens3", CIDRs: []string{"203.0.113.7/24", "fe80::1/64"}},
		{Name: "ens4", CIDRs: []string{"192.168.0.57/24", "fe80::2/64"}},
		{Name: "ens5", CIDRs: []string{"169.254.12.7/16"}},
		{Name: "ens6", CIDRs: []string{"100.64.3.4/10"}},
		{Name: "ens7", CIDRs: []string{"2001:db8::10/64", "10.20.30.40/8"}},
	}
}

func TestDevModeListensEverywhere(t *testing.T) {
	set := Compute(true, []string{"192.168.11.1/24"}, ifaces())
	if set.Mode != ModeDev || len(set.Addrs) != 1 || set.Addrs[0].IP != Wildcard {
		t.Fatalf("dev: %+v", set)
	}
}

func TestPreRolesPrivateAndLinkLocalOnly(t *testing.T) {
	set := Compute(false, nil, ifaces())
	if set.Mode != ModePreRoles {
		t.Fatalf("mode = %s", set.Mode)
	}
	want := []string{Loopback, "10.20.30.40", "169.254.12.7", "192.168.0.57"}
	if got := set.IPs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pre-roles ips = %v, want %v", got, want)
	}
	if set.Addrs[3].Iface != "ens4" {
		t.Fatalf("iface for 192.168.0.57 = %q", set.Addrs[3].Iface)
	}
}

func TestRolesOnlyLoopbackAndLAN(t *testing.T) {
	set := Compute(false, []string{"192.168.11.1/24", "10.99.0.1/24"}, ifaces())
	if set.Mode != ModeRoles {
		t.Fatalf("mode = %s", set.Mode)
	}

	want := []string{Loopback, "10.99.0.1", "192.168.11.1"}
	if got := set.IPs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("roles ips = %v, want %v", got, want)
	}
}

func TestRolesIgnoreBrokenCIDR(t *testing.T) {
	set := Compute(false, []string{"nope", "2001:db8::1/64"}, ifaces())
	if set.Mode != ModePreRoles {
		t.Fatalf("битые/IPv6 адреса ролей не должны включать режим ролей: %+v", set)
	}
}

func TestPreRoleAllowed(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":      true,
		"172.16.5.5":    true,
		"172.32.0.1":    false,
		"192.168.1.1":   true,
		"169.254.1.1":   true,
		"100.64.0.1":    false,
		"203.0.113.1":   false,
		"127.0.0.1":     false,
		"fd00::1":       false,
		"fe80::1":       false,
		"192.0.2.1":     false,
		"192.168.255.9": true,
	}
	for s, want := range cases {
		if got := PreRoleAllowed(net.ParseIP(s)); got != want {
			t.Errorf("%s: got %v, want %v", s, got, want)
		}
	}
}

func TestLoopbackAlwaysFirst(t *testing.T) {
	set := Compute(false, nil, []Interface{{Name: "a", CIDRs: []string{"10.0.0.1/8"}}})
	if set.Addrs[0].IP != Loopback {
		t.Fatalf("loopback обязан идти первым: %v", set.IPs())
	}
}

func TestNoInterfacesStillLoopback(t *testing.T) {
	set := Compute(false, nil, nil)
	if !reflect.DeepEqual(set.IPs(), []string{Loopback}) {
		t.Fatalf("без карт остаётся loopback: %v", set.IPs())
	}
}
