package nftgen

import (
	"strings"
	"testing"
)

func planWithPanel() FirewallPlan {
	return FirewallPlan{
		WANs:  []string{"ens3"},
		LANs:  []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}},
		Panel: &FirewallPanel{Ports: []int{443, 80}, PerSourceConns: 16, TotalNewPerSecond: 200},
	}
}

func TestPanelLimitsFrozen(t *testing.T) {
	if PanelNewPerSecond != 10 || PanelNewBurst != 30 {
		t.Fatalf("предел новых соединений с адреса изменён: %d/с, запас %d", PanelNewPerSecond, PanelNewBurst)
	}

	if PanelNewPerCore != 100 || PanelTotalFloor != 100 || PanelTotalCeiling != 1000 || PanelTotalBurstFactor != 2 {
		t.Fatal("форма совокупного предела изменена")
	}
	for cores, want := range map[int]int{0: 100, 1: 100, 2: 200, 4: 400, 10: 1000, 64: 1000} {
		if got := PanelTotalNewPerSecond(cores); got != want {
			t.Fatalf("ядер %d: предел %d, ожидалось %d", cores, got, want)
		}
	}
	if panelSetSize != 4096 || panelNewTimeout != "60s" {
		t.Fatalf("потолок или срок наборов изменён: %d, %s", panelSetSize, panelNewTimeout)
	}
}

func TestNoPanelNoRules(t *testing.T) {
	p := planWithPanel()
	p.Panel = nil
	out := string(p.Generate())
	for _, needle := range []string{SetPanelConns, SetPanelNew, "ct count", "limit rate over"} {
		if strings.Contains(out, needle) {
			t.Fatalf("без плана панели в рулсете есть %q:\n%s", needle, out)
		}
	}
}

func TestPanelSetsBounded(t *testing.T) {
	p := planWithPanel()
	out := string(p.Generate())
	if !strings.Contains(out, "set panel_conns {\n\t\ttype ipv4_addr\n\t\tsize 4096\n\t\tflags dynamic\n\t}") {
		t.Fatalf("набор счёта соединений не тот:\n%s", out)
	}
	if !strings.Contains(out, "set panel_new {\n\t\ttype ipv4_addr\n\t\tsize 4096\n\t\tflags dynamic,timeout\n\t\ttimeout 60s\n\t}") {
		t.Fatalf("набор частоты не тот:\n%s", out)
	}
}

func TestPanelRulesBeforeLANAccept(t *testing.T) {
	p := planWithPanel()
	out := string(p.Generate())
	want := []string{
		`iifname { "ens4" } tcp dport { 80, 443 } ct state new add @panel_conns { ip saddr ct count over 16 } counter drop`,
		`iifname { "ens4" } tcp dport { 80, 443 } ct state new add @panel_new { ip saddr limit rate over 10/second burst 30 packets } counter drop`,
		`iifname { "ens4" } tcp dport { 80, 443 } ct state new limit rate over 200/second burst 400 packets counter drop`,
		`iifname { "ens4" } accept`,
	}
	last := -1
	for _, w := range want {
		i := strings.Index(out, w)
		if i < 0 {
			t.Fatalf("нет правила %q:\n%s", w, out)
		}
		if i < last {
			t.Fatalf("правило %q стоит раньше предыдущего:\n%s", w, out)
		}
		last = i
	}

	fwd := out[strings.Index(out, "chain forward"):]
	if strings.Contains(fwd, "panel_") {
		t.Fatalf("пределы панели попали в forward:\n%s", fwd)
	}
}

func TestPanelRulesOnlyOnLAN(t *testing.T) {
	p := planWithPanel()
	out := string(p.Generate())
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "panel_") && strings.Contains(line, `"ens3"`) {
			t.Fatalf("правило пределов упоминает WAN: %s", line)
		}
	}
}

func TestValidatePanelRejects(t *testing.T) {
	cases := map[string]*FirewallPanel{
		"без портов":         {PerSourceConns: 16, TotalNewPerSecond: 200},
		"порт вне диапазона": {Ports: []int{70000}, PerSourceConns: 16, TotalNewPerSecond: 200},
		"порт дважды":        {Ports: []int{443, 443}, PerSourceConns: 16, TotalNewPerSecond: 200},
		"нулевой предел":     {Ports: []int{443}, TotalNewPerSecond: 200},
		"нулевой совокупный": {Ports: []int{443}, PerSourceConns: 16},
	}
	for name, panel := range cases {
		p := planWithPanel()
		p.Panel = panel
		if err := p.Validate(known()); err == nil {
			t.Fatalf("%s: план принят", name)
		}
	}
	ok := planWithPanel()
	if err := ok.Validate(known()); err != nil {
		t.Fatalf("исправный план отвергнут: %v", err)
	}
}
