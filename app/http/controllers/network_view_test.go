package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func TestNetworkPageKeepsFormContract(t *testing.T) {
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "network.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"dhcp", "static", "pppoe"} {
		rows := []ifaceView{
			{Name: "eth0", MAC: "aa", State: "UP", Role: "lan", CIDR: "192.168.10.1/24", WANMethod: "dhcp"},
			{Name: "eth1", MAC: "bb", State: "UP", Role: "wan", WANMethod: method, Gateway: "203.0.113.1", VLAN: "100", VLANIface: "eth1.100", Provider: true, SpeedMbit: 1000},
		}
		routes := []netstatus.Route{{Via: "203.0.113.1", Dev: "eth1", Metric: 100}}
		data := map[string]any{"title": "Сеть", "active": "network", "ifaces": rows, "wan": rows[1], "routes": routes,
			"hero": networkHero(rows, routes), "wanMethods": networkMethods(rows[1]), "csrf": "tok"}
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "network.tmpl", data); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		html := buf.String()
		for _, want := range []string{
			`name="role_eth0" value="lan" checked`, `name="role_eth1" value="wan" checked`,
			`name="wanmethod_eth1" value="` + method + `"`, `name="cidr_eth0"`, `name="gateway_eth1"`,
			`name="pppoeuser_eth1"`, `name="vlan_eth1"`, `action="/network/apply"`, "Интернет через eth1, офис на eth0",
		} {
			if !strings.Contains(html, want) {
				t.Fatalf("%s: на странице нет %q", method, want)
			}
		}
		if strings.Count(html, " checked") < 3 {
			t.Fatalf("%s: отмечено меньше трёх вариантов (две роли и способ)", method)
		}
	}
}
