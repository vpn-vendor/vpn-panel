package nftgen

import (
	"strings"
	"testing"
)

func chainBody(t *testing.T, ruleset, name string) string {
	t.Helper()
	i := strings.Index(ruleset, "chain "+name+" {")
	if i < 0 {
		t.Fatalf("нет цепочки %s:\n%s", name, ruleset)
	}
	rest := ruleset[i:]
	return rest[:strings.Index(rest, "\n\t}")]
}

func establishedLines(chain string) []string {
	var out []string
	for _, ln := range strings.Split(chain, "\n") {
		if strings.Contains(ln, "ct state established") {
			out = append(out, strings.TrimSpace(ln))
		}
	}
	return out
}

func TestEstablishedBoundToPath(t *testing.T) {
	white := blackPlan()
	white.Tunnel = nil
	for name, c := range map[string]struct {
		plan    FirewallPlan
		allowed string
	}{
		"защищённый": {blackPlan(), `oifname { "ens4", "wg-vpn0" }`},
		"прямой":     {white, `oifname { "ens3", "ens4" }`},
	} {
		out := string(c.plan.Generate())
		fwd := establishedLines(chainBody(t, out, "forward"))
		if len(fwd) != 1 || !strings.Contains(fwd[0], c.allowed) {
			t.Errorf("%s: продолжение транзита не по разрешённому пути: %q", name, fwd)
		}
	}
	black := blackPlan()
	out := string(black.Generate())
	for _, ln := range establishedLines(chainBody(t, out, "forward")) {
		if strings.Contains(ln, `"ens3"`) {
			t.Errorf("защищённый режим: продолжение транзита к провайдеру: %s", ln)
		}
	}
	for _, ln := range establishedLines(chainBody(t, out, "output")) {
		if !strings.Contains(ln, "ct direction reply") {
			t.Errorf("выход шлюза продолжает свои соединения мимо разрешённых путей: %s", ln)
		}
	}
}
