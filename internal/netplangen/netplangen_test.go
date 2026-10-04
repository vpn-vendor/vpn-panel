package netplangen

import (
	"os"
	"strings"
	"testing"
)

func known() map[string]bool {
	return map[string]bool{"ens3": true, "ens4": true, "enp5s0": true}
}

func TestGenerateWANLANNetworkd(t *testing.T) {
	p := Plan{Interfaces: []PlanInterface{
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
	}}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate(RendererNetworkd, nil))
	want := `network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
        route-metric: 100
      nameservers:
        addresses: [9.9.9.9, 149.112.112.112]
      dhcp6: false
      accept-ra: false
      link-local: []
    ens4:
      dhcp4: false
      addresses: [192.168.11.1/24]
      dhcp6: false
      accept-ra: false
      link-local: []
`
	if out != want {
		t.Fatalf("yaml mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

func TestGenerateNMRenderer(t *testing.T) {
	p := Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: RoleWAN, Method: MethodDHCP}}}
	out := string(p.Generate(RendererNM, nil))
	if !strings.Contains(out, "renderer: NetworkManager") {
		t.Fatalf("want NM renderer, got:\n%s", out)
	}
}

func TestDeterministicOrder(t *testing.T) {
	a := Plan{Interfaces: []PlanInterface{
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "10.10.0.1/24"},
	}}
	b := Plan{Interfaces: []PlanInterface{a.Interfaces[1], a.Interfaces[0]}}
	if string(a.Generate("", nil)) != string(b.Generate("", nil)) {
		t.Fatal("generation must not depend on input order")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		plan Plan
	}{
		{"unknown nic", Plan{Interfaces: []PlanInterface{{Name: "eth9", Role: RoleWAN, Method: MethodDHCP}}}},
		{"bad name", Plan{Interfaces: []PlanInterface{{Name: "../etc", Role: RoleWAN, Method: MethodDHCP}}}},
		{"dup", Plan{Interfaces: []PlanInterface{
			{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
			{Name: "ens3", Role: RoleLAN, Method: MethodStatic, CIDR: "10.0.0.1/24"},
		}}},
		{"wan static без шлюза", Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: RoleWAN, Method: MethodStatic, CIDR: "1.2.3.4/24"}}}},
		{"wan static кривой адрес", Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: RoleWAN, Method: MethodStatic, CIDR: "нет", Gateway: "1.2.3.1"}}}},
		{"lan bad cidr", Plan{Interfaces: []PlanInterface{{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.1.1"}}}},
		{"lan overlap", Plan{Interfaces: []PlanInterface{
			{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.1.1/24"},
			{Name: "enp5s0", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.1.100/25"},
		}}},
		{"bad role", Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: "opt", Method: MethodDHCP}}}},
		{"empty", Plan{}},
	}
	for _, c := range cases {
		if err := c.plan.Validate(known()); err == nil {
			t.Fatalf("%s: want error, got nil", c.name)
		}
	}
}

const statusSample = `{"netplan-global-state":{"online":true,"nameservers":{"addresses":["127.0.0.53"]}},` +
	`"ens3":{"index":2,"adminstate":"UP","operstate":"UP","type":"ethernet","backend":"NetworkManager","id":"wan","macaddress":"52:54:00:12:34:01"},` +
	`"ens4":{"index":3,"adminstate":"UP","operstate":"UP","type":"ethernet","backend":"NetworkManager","id":"NM-1c5e2b3a-8c1e-4f10-9b7f-0a1b2c3d4e5f","macaddress":"52:54:00:12:34:02"},` +
	`"lo":{"index":1,"type":"loopback"},` +
	`"bad":{"id":"x; rm -rf /"}}`

func TestParseStatusIDs(t *testing.T) {
	ids := ParseStatusIDs([]byte(statusSample))
	if ids["ens3"] != "wan" {
		t.Fatalf("ens3 id = %q, want wan", ids["ens3"])
	}
	if ids["ens4"] != "NM-1c5e2b3a-8c1e-4f10-9b7f-0a1b2c3d4e5f" {
		t.Fatalf("ens4 id = %q", ids["ens4"])
	}
	if _, ok := ids["lo"]; ok {
		t.Fatal("интерфейс без id не должен попадать в карту")
	}
	if _, ok := ids["bad"]; ok {
		t.Fatal("имя определения с недопустимыми символами обязано отбрасываться")
	}
	if ParseStatusIDs([]byte("not json")) != nil {
		t.Fatal("битый JSON — nil")
	}
}

func TestGenerateMergesIntoExistingDefinitions(t *testing.T) {
	plan := Plan{Interfaces: []PlanInterface{
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
	}}
	ids := ParseStatusIDs([]byte(statusSample))
	out := string(plan.Generate(RendererNM, ids))
	if !strings.Contains(out, "    wan:\n      dhcp4: true") {
		t.Fatalf("WAN обязан писаться под чужим определением wan:\n%s", out)
	}
	if !strings.Contains(out, "    NM-1c5e2b3a-8c1e-4f10-9b7f-0a1b2c3d4e5f:\n      dhcp4: false\n      addresses: [192.168.11.1/24]") {
		t.Fatalf("LAN обязан писаться под определением NM:\n%s", out)
	}
	if strings.Contains(out, "    ens4:") || strings.Contains(out, "    ens3:") {
		t.Fatalf("конкурирующих определений по имени быть не должно:\n%s", out)
	}

	if !strings.Contains(string(plan.Generate(RendererNM, nil)), "    ens4:") {
		t.Fatal("без карты ключом остаётся имя интерфейса")
	}
}

func TestIPv6DisabledNMUsesPassthrough(t *testing.T) {
	plan := Plan{Interfaces: []PlanInterface{
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
	}}
	out := string(plan.Generate(RendererNM, nil))
	if strings.Count(out, "ipv6.method: disabled") != 2 {
		t.Fatalf("обе карты обязаны получить ipv6.method: disabled:\n%s", out)
	}
	if strings.Contains(out, "accept-ra") || strings.Contains(out, "link-local") {
		t.Fatalf("под NM ключи accept-ra/link-local бесполезны и не пишутся:\n%s", out)
	}
}

func TestIPv6EnabledPerRole(t *testing.T) {
	plan := Plan{IPv6: true, Interfaces: []PlanInterface{
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
	}}
	nd := string(plan.Generate(RendererNetworkd, nil))
	if !strings.Contains(nd, "    ens3:\n      dhcp4: true\n      dhcp4-overrides:\n        use-dns: false\n        route-metric: 100\n      nameservers:\n        addresses: [9.9.9.9, 149.112.112.112]\n      dhcp6: true\n      accept-ra: true\n") {
		t.Fatalf("WAN при включённом IPv6 принимает RA и DHCPv6:\n%s", nd)
	}
	if !strings.Contains(nd, "    ens4:\n      dhcp4: false\n      addresses: [192.168.11.1/24]\n      dhcp6: false\n      accept-ra: false\n") {
		t.Fatalf("LAN при включённом IPv6 не принимает RA:\n%s", nd)
	}
	if strings.Contains(nd, "link-local: []") {
		t.Fatal("при включённом IPv6 link-local не запрещается")
	}
	nm := string(plan.Generate(RendererNM, nil))
	if strings.Contains(nm, "ipv6.method: disabled") {
		t.Fatalf("при включённом IPv6 под NM disabled недопустим:\n%s", nm)
	}
	if strings.Count(nm, "ipv6.method: link-local") != 1 {
		t.Fatalf("LAN под NM — только link-local:\n%s", nm)
	}
}

func TestNMPassthroughPriorityOnlyForNM(t *testing.T) {
	plan := Plan{Interfaces: []PlanInterface{{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"}}}
	nm := string(plan.Generate(RendererNM, nil))
	if !strings.Contains(nm, "connection.autoconnect-priority: \"100\"") {
		t.Fatalf("для NM обязателен приоритет автоподключения:\n%s", nm)
	}
	if strings.Contains(string(plan.Generate(RendererNetworkd, nil)), "networkmanager:") {
		t.Fatal("для networkd блок networkmanager недопустим")
	}
	ids := plan.DefinitionIDs(map[string]string{"ens4": "NM-abc"})
	if len(ids) != 1 || ids[0] != "NM-abc" || NMConnectionName(ids[0]) != "netplan-NM-abc" {
		t.Fatalf("DefinitionIDs/NMConnectionName: %v", ids)
	}
}

func TestGenerateStaticWAN(t *testing.T) {
	p := Plan{Interfaces: []PlanInterface{
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
		{Name: "ens3", Role: RoleWAN, Method: MethodStatic, CIDR: "203.0.113.45/24",
			Gateway: "203.0.113.1", DNS: []string{"9.9.9.9"}, Metric: 100},
	}}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("статический WAN обязан быть валиден: %v", err)
	}
	out := string(p.Generate(RendererNetworkd, nil))
	for _, want := range []string{
		"addresses: [203.0.113.45/24]",
		"routes:",
		"- to: default",
		"via: 203.0.113.1",
		"metric: 100",
		"addresses: [9.9.9.9]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q в:\n%s", want, out)
		}
	}

	if strings.Count(out, "to: default") != 1 {
		t.Fatalf("маршрут по умолчанию должен быть ровно один (WAN):\n%s", out)
	}
}

func TestMethodsCoexistThroughRegistry(t *testing.T) {
	if _, ok := l3Renderers[MethodDHCP]; !ok {
		t.Fatal("DHCP обязан быть в реестре рендереров")
	}
	if _, ok := l3Renderers[MethodStatic]; !ok {
		t.Fatal("статика обязана быть в реестре рендереров")
	}

	if methodOf(PlanInterface{Role: RoleWAN}) != MethodDHCP {
		t.Fatal("пустой метод WAN обязан означать DHCP")
	}
	if methodOf(PlanInterface{Role: RoleLAN}) != MethodStatic {
		t.Fatal("пустой метод LAN обязан означать статику")
	}
}

func TestAddressHelpers(t *testing.T) {
	if p, ok := MaskToPrefix("255.255.255.0"); !ok || p != 24 {
		t.Fatalf("маска /24: %d %v", p, ok)
	}
	if p, ok := MaskToPrefix("255.255.255.248"); !ok || p != 29 {
		t.Fatalf("маска /29: %d %v", p, ok)
	}
	if _, ok := MaskToPrefix("255.0.255.0"); ok {
		t.Fatal("несплошная маска — не маска")
	}
	if m, ok := PrefixToMask(24); !ok || m != "255.255.255.0" {
		t.Fatalf("/24 → %q", m)
	}

	if a, pfx, ok := ParseAddrField("203.0.113.45/29"); !ok || a != "203.0.113.45" || pfx != 29 {
		t.Fatalf("CIDR-поле: %q %d %v", a, pfx, ok)
	}

	if a, pfx, ok := ParseAddrField("203.0.113.45"); !ok || a != "203.0.113.45" || pfx != -1 {
		t.Fatalf("голый адрес: %q %d %v", a, pfx, ok)
	}

	if p, reason, ok := SuggestPrefix("203.0.113.45", "203.0.113.1"); !ok || p != 24 || reason == "" {
		t.Fatalf("предложение /24: %d %q %v", p, reason, ok)
	}

	if p, _, ok := SuggestPrefix("203.0.112.45", "203.0.113.1"); !ok || p != 23 {
		t.Fatalf("расширение до /23: %d %v", p, ok)
	}

	if _, _, ok := SuggestPrefix("203.0.113.45", "10.0.0.1"); ok {
		t.Fatal("несовместимые адрес и шлюз — предложения быть не должно")
	}

	if GatewayConsistent("203.0.113.45", 24, "203.0.113.1") != true {
		t.Fatal("шлюз .1 при /24 согласован с .45")
	}
	if GatewayConsistent("203.0.113.45", 24, "10.0.0.1") != false {
		t.Fatal("шлюз в другой сети — несогласован (предупреждение)")
	}

	if GatewayConsistent("203.0.113.45", 31, "203.0.113.44") != true {
		t.Fatal("/31 — шлюз on-link, согласован")
	}
}

func TestEffectiveWANIsNicForCurrentMethods(t *testing.T) {
	if EffectiveWAN("ens3", MethodDHCP) != "ens3" {
		t.Fatal("DHCP: действующий WAN — сама карта")
	}
	if EffectiveWAN("ens3", MethodStatic) != "ens3" {
		t.Fatal("static: действующий WAN — сама карта")
	}
	if EffectiveWAN("ens3", "") != "ens3" {
		t.Fatal("пустой метод: действующий WAN — сама карта")
	}
}

func TestPPPoEThroughSeam(t *testing.T) {

	if EffectiveWAN("ens3", MethodPPPoE) != IfacePPPoE {
		t.Fatalf("PPPoE: действующий WAN — %s, а не карта", IfacePPPoE)
	}
	if _, ok := l3Renderers[MethodPPPoE]; !ok {
		t.Fatal("PPPoE обязан быть в реестре рендереров")
	}

	p := Plan{Interfaces: []PlanInterface{
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
		{Name: "ens3", Role: RoleWAN, Method: MethodPPPoE, Username: "user@isp"},
	}}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("PPPoE с логином валиден: %v", err)
	}
	out := string(p.Generate(RendererNetworkd, nil))
	if !strings.Contains(out, "dhcp4: false") {
		t.Fatalf("база PPPoE — линк без L3:\n%s", out)
	}

	if strings.Count(out, "addresses:") != 1 {
		t.Fatalf("адрес должен быть только у LAN (один):\n%s", out)
	}

	p.Interfaces[1].Username = ""
	if err := p.Validate(known()); err == nil {
		t.Fatal("PPPoE без логина обязан отклоняться")
	}
}

func TestEffectiveWANsAnnouncesProvisioned(t *testing.T) {

	pppoe := Plan{Interfaces: []PlanInterface{
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
		{Name: "ens3", Role: RoleWAN, Method: MethodPPPoE, Username: "user@isp"},
	}}
	got := pppoe.EffectiveWANs()
	if len(got) != 1 || got[0] != IfacePPPoE {
		t.Fatalf("PPPoE: действующий WAN должен быть %q, получено %v", IfacePPPoE, got)
	}

	dhcp := Plan{Interfaces: []PlanInterface{
		{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
		{Name: "ens3", Role: RoleWAN, Method: MethodDHCP},
	}}
	got = dhcp.EffectiveWANs()
	if len(got) != 1 || got[0] != "ens3" {
		t.Fatalf("DHCP: действующий WAN — сама карта ens3, получено %v", got)
	}
}

func TestVLANIsOverlayOverMethod(t *testing.T) {
	base := func(m string, extra func(*PlanInterface)) Plan {
		wan := PlanInterface{Name: "ens3", Role: RoleWAN, Method: m, VLAN: 100}
		if extra != nil {
			extra(&wan)
		}
		return Plan{Interfaces: []PlanInterface{
			{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"}, wan}}
	}

	pd := base(MethodDHCP, nil)
	out := string(pd.Generate(RendererNetworkd, nil))
	for _, want := range []string{"  vlans:\n", "    ens3.100:\n", "      id: 100\n",
		"      link: ens3\n", "dhcp4: true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q в:\n%s", want, out)
		}
	}
	if strings.Count(out, "dhcp4: true") != 1 {
		t.Fatalf("адрес должен просить только подынтерфейс:\n%s", out)
	}

	ps := base(MethodStatic, func(w *PlanInterface) {
		w.CIDR, w.Gateway = "203.0.113.45/24", "203.0.113.1"
	})
	out = string(ps.Generate(RendererNetworkd, nil))
	vl := out[strings.Index(out, "  vlans:"):]
	if !strings.Contains(vl, "203.0.113.45/24") || !strings.Contains(vl, "via: 203.0.113.1") {
		t.Fatalf("статика обязана быть на подынтерфейсе:\n%s", out)
	}

	pp := base(MethodPPPoE, func(w *PlanInterface) { w.Username = "u@isp" })
	out = string(pp.Generate(RendererNetworkd, nil))
	if strings.Contains(out, "addresses:") && strings.Count(out, "addresses:") != 1 {
		t.Fatalf("у PPPoE поверх тега адрес только у LAN:\n%s", out)
	}
	if !strings.Contains(out, "    ens3.100:\n") {
		t.Fatalf("подынтерфейс обязан быть создан и под PPPoE:\n%s", out)
	}
}

func TestEffectiveWANOverVLAN(t *testing.T) {
	if got := EffectiveWAN(LinkIface("ens3", 100), MethodDHCP); got != "ens3.100" {
		t.Fatalf("dhcp поверх тега: %q", got)
	}
	if got := EffectiveWAN(LinkIface("ens3", 100), MethodPPPoE); got != IfacePPPoE {
		t.Fatalf("pppoe поверх тега: %q", got)
	}

	if got := LinkIface("enp130s0f1np1", 100); got != "vlan100" {
		t.Fatalf("запасное имя: %q", got)
	}
	if got := LinkIface("ens3", 0); got != "ens3" {
		t.Fatalf("без тега — сама карта: %q", got)
	}

	p := Plan{Interfaces: []PlanInterface{{Name: "ens3", Role: RoleWAN, Method: MethodDHCP, VLAN: 100}}}
	ids := p.DefinitionIDs(nil)
	if len(ids) != 2 || ids[0] != "ens3" || ids[1] != "ens3.100" {
		t.Fatalf("определения плана: %v", ids)
	}
}

func TestVLANValidation(t *testing.T) {
	mk := func(role string, vlan int) Plan {
		return Plan{Interfaces: []PlanInterface{
			{Name: "ens4", Role: RoleLAN, Method: MethodStatic, CIDR: "192.168.11.1/24"},
			{Name: "ens3", Role: role, Method: MethodDHCP, VLAN: vlan}}}
	}
	bad := mk(RoleWAN, 4095)
	if err := bad.Validate(known()); err == nil {
		t.Fatal("тег 4095 зарезервирован и обязан отвергаться")
	}
	zero := mk(RoleWAN, 0)
	if err := zero.Validate(known()); err != nil {
		t.Fatalf("ноль — это «без тега», не ошибка: %v", err)
	}
	good := mk(RoleWAN, 100)
	if err := good.Validate(known()); err != nil {
		t.Fatalf("тег 100 на WAN законен: %v", err)
	}
}

func TestVLANNamingMatchesUI(t *testing.T) {
	js, err := os.ReadFile("../../public/js/network.js")
	if err != nil {
		t.Fatalf("подсказка формы не найдена: %v", err)
	}
	text := string(js)
	for _, want := range []string{
		"IFNAME_MAX = 15",
		"VLAN_MAX = 4094",
		"\"vlan\" + tag",
		"nic + \".\" + tag",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("в подсказке формы нет %q — правило имени разошлось с LinkIface", want)
		}
	}
	if MaxVLANID != 4094 {
		t.Fatalf("предел тега изменился (%d) — поправьте и подсказку формы", MaxVLANID)
	}

	if LinkIface("abcdefghijk", 100) != "abcdefghijk.100" {
		t.Fatal("имя длиной ровно 15 обязано использоваться как есть")
	}
	if LinkIface("abcdefghijkl", 100) != "vlan100" {
		t.Fatal("имя длиннее предела обязано заменяться коротким")
	}
}
