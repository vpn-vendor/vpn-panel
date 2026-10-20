package nftgen

import (
	"slices"
	"strings"
	"testing"
)

func witnessPlans() map[string]FirewallPlan {
	bare := blackPlan()
	bare.Tunnel = &FirewallTunnel{Iface: "wg-vpn0"}
	return map[string]FirewallPlan{
		"прямой": {WANs: []string{"ppp0", "ens3"},
			LANs: []FirewallLAN{{Name: "ens5", CIDR: "10.0.5.1/24"}, {Name: "ens4", CIDR: "192.168.77.1/24"}}},
		"защищённый":             blackPlan(),
		"защищённый без сервера": bare,
		"пробный":                ProbePlan(),
	}
}

func lastRule(t *testing.T, ruleset, chain string) string {
	t.Helper()
	lines := strings.Split(chainBody(t, ruleset, chain), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func verdicts(body string) []string {
	var out []string
	for _, ln := range strings.Split(body, "\n")[2:] {
		for _, w := range strings.Fields(ln) {
			switch w {
			case "accept", "drop", "reject", "jump", "goto", "queue":
				out = append(out, strings.TrimSpace(ln))
			}
		}
	}
	return out
}

func withoutWitnesses(s string) string {
	var out []string
	skip := false
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(ln, "\tcounter seen_") || strings.HasPrefix(ln, "\tchain witness_") {
			skip = true
		}
		if !skip {
			out = append(out, ln)
		}
		if skip && ln == "\t}" {
			skip = false
		}
	}
	return strings.Join(out, "\n")
}

func TestWitnessGolden(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}}}
	out := string(p.Generate(Caps{Witness: true}))
	want := []string{
		"\t}\n\tcounter seen_early {\n\t\tpackets 0 bytes 0\n\t}\n\tcounter seen_late {\n\t\tpackets 0 bytes 0\n\t}\n\tchain postrouting {\n",
		`		iifname { "ens4" } oifname { "ens3" } accept
	}
	chain witness_early {
		type filter hook forward priority raw - 10; policy accept;
		ct state != new return
		udp dport 3544 return
		meta l4proto 41 return
		meta nfproto != ipv4 return
		iifname { "ens4" } oifname { "ens3" } counter name "seen_early"
	}
	chain witness_late {
		type filter hook forward priority security + 10; policy accept;
		ct state != new return
		udp dport 3544 return
		meta l4proto 41 return
		meta nfproto != ipv4 return
		iifname { "ens4" } oifname { "ens3" } counter name "seen_late"
	}
`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("нет фрагмента:\n%s\n--- набор ---\n%s", w, out)
		}
	}
	if strings.LastIndex(out, "\tset ") > strings.Index(out, "\tcounter seen_early") ||
		strings.Index(out, "\tcounter seen_late") > strings.Index(out, "\tchain ") {
		t.Fatalf("счётчики обязаны стоять после наборов и до цепочек:\n%s", out)
	}
}

func TestWitnessOnlyAdds(t *testing.T) {
	for name, p := range witnessPlans() {
		base := string(p.Generate(Caps{}))
		with := string(p.Generate(Caps{Witness: true}))
		if with == base {
			t.Fatalf("%s: флаг свидетелей ничего не добавил", name)
		}
		if got := withoutWitnesses(with); got != base {
			t.Errorf("%s: свидетели изменили базовый набор:\n%s", name, got)
		}
		if strings.Contains(base, "witness") || strings.Contains(base, "seen_") {
			t.Errorf("%s: свидетели без флага:\n%s", name, base)
		}
	}
}

func TestWitnessHasNoVerdict(t *testing.T) {
	for name, p := range witnessPlans() {
		out := string(p.Generate(Caps{Witness: true}))
		if len(verdicts(chainBody(t, out, "forward"))) == 0 {
			t.Fatalf("%s: контроль не видит вердиктов в forward", name)
		}
		for _, chain := range []string{WitnessEarlyChain, WitnessLateChain} {
			body := chainBody(t, out, chain)
			if v := verdicts(body); len(v) > 0 {
				t.Errorf("%s: свидетель %s решает судьбу пакета: %q", name, chain, v)
			}
			if !strings.Contains(body, "policy accept;") {
				t.Errorf("%s: свидетель %s обязан пропускать всё:\n%s", name, chain, body)
			}
			for _, ln := range strings.Split(body, "\n")[2:] {
				ln = strings.TrimSpace(ln)
				if !strings.HasSuffix(ln, " return") && !strings.Contains(ln, " counter name ") {
					t.Errorf("%s: в свидетеле %s лишнее правило: %q", name, chain, ln)
				}
			}
		}
	}
}

func TestWitnessMatchesForwardAllow(t *testing.T) {
	for name, p := range witnessPlans() {
		out := string(p.Generate(Caps{Witness: true}))
		allow, ok := strings.CutSuffix(lastRule(t, out, "forward"), " accept")
		if !ok {
			t.Fatalf("%s: последнее правило forward — не разрешение", name)
		}
		for chain, counter := range map[string]string{WitnessEarlyChain: SeenEarlyCounter, WitnessLateChain: SeenLateCounter} {
			got, ok := strings.CutSuffix(lastRule(t, out, chain), ` counter name "`+counter+`"`)
			if !ok || got != allow {
				t.Errorf("%s: свидетель %s считает %q, а forward разрешает %q", name, chain, got, allow)
			}
		}

		excepts := map[string]string{
			"udp dport 3544 drop":    "udp dport 3544 return",
			"meta l4proto 41 drop":   "meta l4proto 41 return",
			"meta nfproto ipv6 drop": "meta nfproto != ipv4 return",
		}
		found := map[string]bool{}
		for _, ln := range strings.Split(chainBody(t, out, "forward"), "\n")[2:] {
			ln = strings.TrimSpace(ln)
			if !slices.Contains(strings.Fields(ln), "drop") {
				continue
			}
			ex := ""
			for d, e := range excepts {
				if ln == d || strings.HasSuffix(ln, " "+d) {
					ex = e
					found[d] = true
				}
			}
			if ex == "" {
				t.Errorf("%s: drop в forward без исключения в свидетеле: %q", name, ln)
				continue
			}
			for _, chain := range []string{WitnessEarlyChain, WitnessLateChain} {
				if !strings.Contains(chainBody(t, out, chain)+"\n", "\t\t"+ex+"\n") {
					t.Errorf("%s: в свидетеле %s нет исключения %q", name, chain, ex)
				}
			}
		}
		if len(found) != len(excepts) {
			t.Errorf("%s: в forward нашли не все свои drop: %v", name, found)
		}
		for _, exit := range p.Exits() {
			if !strings.Contains(allow, `"`+exit+`"`) {
				t.Errorf("%s: выход %s не в разрешении: %q", name, exit, allow)
			}
		}
		if p.Black() {
			for _, wan := range p.WANs {
				if strings.Contains(allow, `"`+wan+`"`) {
					t.Errorf("%s: защищённый режим считает выход к провайдеру: %q", name, allow)
				}
			}
		}
	}
}

func forwardPriorities(t *testing.T, ruleset string) map[string]string {
	t.Helper()
	out := map[string]string{}
	chain := ""
	for _, ln := range strings.Split(ruleset, "\n") {
		if name, ok := strings.CutPrefix(ln, "\tchain "); ok {
			chain = strings.TrimSuffix(name, " {")
		}
		if rest, ok := strings.CutPrefix(ln, "\t\ttype filter hook forward priority "); ok {
			prio, _, _ := strings.Cut(rest, ";")
			out[chain] = prio
		}
	}
	return out
}

func TestWitnessPriorityConstants(t *testing.T) {
	for name, p := range witnessPlans() {
		prios := forwardPriorities(t, string(p.Generate(Caps{Witness: true})))
		if len(prios) != 3 {
			t.Fatalf("%s: ждали forward и двух свидетелей, нашли %v", name, prios)
		}
		for chain, want := range map[string]int{WitnessEarlyChain: WitnessEarlyPriority, WitnessLateChain: WitnessLatePriority} {
			if got, ok := PriorityValue(prios[chain]); !ok || got != want {
				t.Errorf("%s: у %s в тексте %q (%d), а константа %d", name, chain, prios[chain], got, want)
			}
		}
		if got, ok := PriorityValue(prios["forward"]); !ok || got <= WitnessEarlyPriority || got >= WitnessLatePriority {
			t.Errorf("%s: forward с приоритетом %q вне окна свидетелей", name, prios["forward"])
		}
	}
}

func TestPriorityValue(t *testing.T) {
	for in, want := range map[string]int{
		"filter": 0, "filter + 10": 10, "filter+10": 10, "filter - 10": -10, "raw - 10": -310,
		"security + 10": 60, "mangle": -150, "dstnat": -100, "srcnat + 10": 110,
		"-310": -310, "100": 100, " 0 ": 0,
	} {
		if got, ok := PriorityValue(in); !ok || got != want {
			t.Errorf("PriorityValue(%q) = %d, %v; ждали %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "bogus", "nat", "filter +", "filter + x", "filter + -5", "filter + +5", "filter + 1 + 2", "+", "Filter"} {
		if got, ok := PriorityValue(in); ok {
			t.Errorf("PriorityValue(%q) = %d: ждали «не понято»", in, got)
		}
	}
}

func TestExits(t *testing.T) {
	black := blackPlan()
	white := blackPlan()
	white.WANs = []string{"ppp0", "ens3"}
	white.Tunnel = nil
	noIface := white
	noIface.Tunnel = &FirewallTunnel{}
	for name, c := range map[string]struct {
		p    FirewallPlan
		want string
	}{
		"защищённый":      {black, "wg-vpn0"},
		"прямой":          {white, "ppp0 ens3"},
		"канал без имени": {noIface, "ppp0 ens3"},
	} {
		if got := strings.Join(c.p.Exits(), " "); got != c.want {
			t.Errorf("%s: выходы %q, ждали %q", name, got, c.want)
		}
	}
}
