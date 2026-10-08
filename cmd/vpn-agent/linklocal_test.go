package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func TestCardsWithoutIPv4(t *testing.T) {
	got := cardsWithoutIPv4([]netstatus.Interface{
		{Name: "lo", Loopback: true, Addresses: []string{"127.0.0.1/8"}},
		{Name: "ens3", Addresses: []string{"192.168.1.5/24", "fe80::1/64"}},
		{Name: "ens4", Addresses: []string{"fe80::2/64"}},
		{Name: "ens5", Addresses: []string{}},
		{Name: "ens3.100", Addresses: []string{}},
		{Name: "ppp0", Addresses: []string{}},
		{Name: "wg-vpn0", Addresses: []string{}},
		{Name: "ifb-vpn0", Addresses: []string{}},
		{Name: "bad name", Addresses: []string{}},
	})
	if want := []string{"ens4", "ens5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("карты без IPv4: %v, ждали %v", got, want)
	}
}

func TestNetworkdDropInFollowsDefinitionID(t *testing.T) {
	base, dropIn := networkdDropIn("ens4", map[string]string{"ens4": "lan"})
	if base != "/run/systemd/network/10-netplan-lan.network" ||
		dropIn != "/run/systemd/network/10-netplan-lan.network.d/vpn-panel-link-local.conf" {
		t.Fatalf("по идентификатору: %s, %s", base, dropIn)
	}
	base, _ = networkdDropIn("ens4", map[string]string{"ens4": "bad id/.."})
	if base != "/run/systemd/network/10-netplan-ens4.network" {
		t.Fatalf("недопустимый идентификатор должен уступить имени карты: %s", base)
	}
	base, _ = networkdDropIn("ens5", nil)
	if base != "/run/systemd/network/10-netplan-ens5.network" {
		t.Fatalf("без идентификатора — имя карты: %s", base)
	}
}

func TestOwnNetworkFileForUndescribedCard(t *testing.T) {
	if p := networkdOwnFile("ens3"); p != "/run/systemd/network/50-vpn-panel-link-local-ens3.network" {
		t.Fatalf("путь своего описания: %s", p)
	}
	if !strings.HasPrefix(linkLocalOwnPrefix, "50-") || linkLocalOwnPrefix >= "zzzz" {
		t.Fatal("своё описание обязано сортироваться раньше умолчания системы (zzzz-…)")
	}
	body := fmt.Sprintf(linkLocalOwnContent, "ens3")
	for _, want := range []string{"Name=ens3", "DHCP=yes", "LinkLocalAddressing=yes"} {
		if !strings.Contains(body, want) {
			t.Errorf("в своём описании нет %q", want)
		}
	}
}

func TestLinkLocalFilesAreVolatile(t *testing.T) {
	for _, p := range []string{linkLocalNMFile, linkLocalNetworkdDir} {
		if len(p) < 5 || p[:5] != "/run/" {
			t.Fatalf("%s не в /run", p)
		}
	}
}
