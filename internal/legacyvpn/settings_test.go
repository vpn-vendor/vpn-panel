package legacyvpn

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func writeAll(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	dhcpdText = "default-lease-time 604800;\nsubnet 192.168.11.0 netmask 255.255.255.0 {\n  range 192.168.11.2 192.168.11.254;\n  option routers 192.168.11.1;\n}\n"
	iscText   = "INTERFACESv4=\"ens3\"\n"
	lanYAML   = "    ens3:\n      addresses: [192.168.11.1/24]\n      optional: true\n"
)

func missing(s Settings) []string {
	var out []string
	for _, m := range s.Missing {
		out = append(out, m.What)
	}
	return out
}

func TestReadSettingsDHCPWAN(t *testing.T) {
	root := writeAll(t, map[string]string{
		scriptNetplan: "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    ens2:\n      dhcp4: true\n" + lanYAML,
		iscDefault:    iscText,
		dhcpdConf:     dhcpdText,
		openvpnConf:   "client\nremote vpn.example.net 1194\ndev tun0\n",
	})
	s := ReadSettings(root)
	if !reflect.DeepEqual(s.WAN, WAN{Card: "ens2", Method: MethodDHCP}) {
		t.Fatalf("WAN: %+v", s.WAN)
	}
	if s.LAN != (LAN{Card: "ens3", CIDR: "192.168.11.1/24"}) {
		t.Fatalf("LAN: %+v", s.LAN)
	}
	if s.DHCP != (DHCP{Subnet: "192.168.11.0/24", RangeStart: "192.168.11.2", RangeEnd: "192.168.11.254", Lease: 604800}) {
		t.Fatalf("DHCP: %+v", s.DHCP)
	}
	if s.VPN == nil || s.VPN.Protocol != ProtocolOpenVPN || s.VPN.Endpoint != "vpn.example.net:1194" || s.VPN.Path != openvpnConf {
		t.Fatalf("VPN: %+v", s.VPN)
	}
	if len(s.Missing) != 0 {
		t.Fatalf("всё прочитано, а отчёт: %+v", s.Missing)
	}
}

func TestReadSettingsStaticWAN(t *testing.T) {
	routes := "network:\n  version: 2\n  ethernets:\n    ens2:\n      addresses: [203.0.113.45/24]\n      routes:\n        - to: default\n          via: 203.0.113.1\n      nameservers:\n        addresses: [9.9.9.9, 149.112.112.112]\n" + lanYAML
	gateway4 := "network:\n  version: 2\n  ethernets:\n    ens2:\n      addresses: [203.0.113.45/24]\n      gateway4: 203.0.113.1\n      nameservers:\n        addresses: [9.9.9.9]\n" + lanYAML
	for name, yaml := range map[string]string{"routes": routes, "gateway4": gateway4} {
		s := ReadSettings(writeAll(t, map[string]string{scriptNetplan: yaml, iscDefault: iscText, dhcpdConf: dhcpdText}))
		if s.WAN.Card != "ens2" || s.WAN.Method != MethodStatic || s.WAN.CIDR != "203.0.113.45/24" || s.WAN.Gateway != "203.0.113.1" || s.WAN.DNS[0] != "9.9.9.9" {
			t.Fatalf("%s: WAN %+v", name, s.WAN)
		}
		if s.VPN != nil || len(s.Missing) != 0 {
			t.Fatalf("%s: VPN %+v, отчёт %+v", name, s.VPN, s.Missing)
		}
	}
}

func TestReadSettingsPPPoE(t *testing.T) {
	root := writeAll(t, map[string]string{ //nolint:gosec
		scriptNetplan: "network:\n  version: 2\n  ethernets:\n    ens2:\n      dhcp4: false\n" + lanYAML,
		PPPoEPeer:     "plugin rp-pppoe.so ens2\nuser \"office@isp\"\nmtu 1492\npersist\n",
		pppdChapFile:  "# Secrets for authentication using CHAP\n\"office@isp\" * \"p@ss word\" *\n",
		iscDefault:    iscText,
		dhcpdConf:     dhcpdText,
		wireguardConf: "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = vpn.example.net:51820\n",
	})
	s := ReadSettings(root)
	if !reflect.DeepEqual(s.WAN, WAN{Card: "ens2", Method: MethodPPPoE, PPPoEUser: "office@isp", PPPoEPassword: true}) {
		t.Fatalf("WAN: %+v", s.WAN)
	}
	if pw, ok := ReadPPPoEPassword(root, "office@isp"); !ok || pw != "p@ss word" {
		t.Fatalf("пароль: %q %v", pw, ok)
	}
	if _, ok := ReadPPPoEPassword(root, "другой"); ok {
		t.Fatal("чужой логин получил пароль")
	}
	if s.VPN == nil || s.VPN.Protocol != ProtocolWireGuard || s.VPN.Endpoint != "vpn.example.net:51820" {
		t.Fatalf("VPN: %+v", s.VPN)
	}
	if len(s.Missing) != 0 {
		t.Fatalf("отчёт: %+v", s.Missing)
	}

	root2 := writeAll(t, map[string]string{
		scriptNetplan: "network:\n  version: 2\n  ethernets:\n" + lanYAML,
		PPPoEPeer:     "plugin pppoe.so nic-ens2\nuser office\n",
		iscDefault:    iscText, dhcpdConf: dhcpdText,
	})
	s2 := ReadSettings(root2)
	if s2.WAN.Method != MethodPPPoE || s2.WAN.PPPoEUser != "office" || s2.WAN.PPPoEPassword || !slices.Equal(missing(s2), []string{"пароль PPPoE"}) {
		t.Fatalf("без пароля: %+v %+v", s2.WAN, s2.Missing)
	}
}

func TestReadSettingsBroken(t *testing.T) {
	s := ReadSettings(t.TempDir())
	if !slices.Equal(missing(s), []string{whatWANCard, whatWAN, whatLAN, whatDHCP}) || s.VPN != nil {
		t.Fatalf("пустой корень: %+v", s.Missing)
	}
	for _, m := range s.Missing {
		if m.Why == "" {
			t.Errorf("нехватка %q без причины", m.What)
		}
	}
	root := writeAll(t, map[string]string{
		scriptNetplan: "network: [не yaml",
		dhcpdConf:     "subnet 192.168.11.0 netmask 255.255.255.0 {\n}\n",
		PPPoEPeer:     "plugin rp-pppoe.so\n",
	})
	s = ReadSettings(root)
	got := strings.Join(missing(s), ",")
	for _, want := range []string{whatWANCard, whatWAN, whatLAN, whatDHCP} {
		if !strings.Contains(got, want) {
			t.Errorf("испорченная копия: нет нехватки %q в %q", want, got)
		}
	}
	if s.WAN.Method != "" || s.LAN.Card != "" || s.DHCP.Subnet != "" {
		t.Fatalf("из мусора что-то прочитано: %+v", s)
	}

	bad := writeAll(t, map[string]string{
		scriptNetplan: "network:\n  version: 2\n  ethernets:\n    \"../x\":\n      dhcp4: true\n" + lanYAML,
		iscDefault:    "INTERFACESv4=\"ens3; rm -rf /\"\n", dhcpdConf: dhcpdText,
	})
	if s := ReadSettings(bad); s.WAN.Card != "" || s.LAN.Card != "ens3" {
		t.Fatalf("негодные имена: %+v", s)
	}
}

func TestVPNConfigPath(t *testing.T) {
	if VPNConfigPath(ProtocolOpenVPN) != openvpnConf || VPNConfigPath(ProtocolWireGuard) != wireguardConf || VPNConfigPath("x") != "" {
		t.Fatal("пути подключений старого скрипта")
	}
}
