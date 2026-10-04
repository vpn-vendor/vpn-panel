package nftgen

import (
	"strings"
	"testing"
)

func blackPlan() FirewallPlan {
	return FirewallPlan{
		WANs: []string{"ens3"},
		LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.11.1/24"}},
		Tunnel: &FirewallTunnel{
			Iface:        "wg-vpn0",
			Endpoint:     "203.0.113.7",
			EndpointPort: 51820,
			Mark:         51820,
		},
	}
}

func outputChain(t *testing.T, p FirewallPlan) string {
	t.Helper()
	got := string(p.Generate())
	i := strings.Index(got, "chain output {")
	if i < 0 {
		return ""
	}
	rest := got[i:]
	j := strings.Index(rest, "\n\t}")
	if j < 0 {
		t.Fatalf("цепочка output не закрыта:\n%s", rest)
	}
	return rest[:j]
}

func TestOutputChainAllowsTunnelToComeUp(t *testing.T) {
	chain := outputChain(t, blackPlan())
	if chain == "" {
		t.Fatal("в чёрном режиме цепочки выхода нет")
	}

	must := []string{
		"ip daddr 203.0.113.7 udp dport 51820 accept",
		"meta mark 0xca6c accept",
		"udp sport 68 udp dport 67 accept",
		"ct state established,related ct direction reply accept",
	}
	for _, want := range must {
		if !strings.Contains(chain, want) {
			t.Errorf("цепочка выхода запирает шлюз: нет правила %q\n%s", want, chain)
		}
	}
}

func TestOutputChainDoesNotOpenNameServers(t *testing.T) {
	chain := outputChain(t, blackPlan())
	for _, forbidden := range []string{"udp dport 53 accept", "tcp dport 53 accept", "udp dport 123 accept"} {
		if strings.Contains(chain, forbidden) {
			t.Errorf("цепочка выхода открывает %q без метки — это утечка публичного адреса офиса", forbidden)
		}
	}
}

func TestOutputChainDropsEverythingElseWithCounter(t *testing.T) {
	chain := outputChain(t, blackPlan())
	lines := strings.Split(strings.TrimRight(chain, "\n"), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	want := "counter drop comment \"" + LeakDropComment + "\""
	if last != want {
		t.Errorf("последнее правило цепочки = %q, ожидалось %q", last, want)
	}
	if !strings.Contains(chain, "meta nfproto ipv6 counter drop") {
		t.Error("новое поколение адресов не закрыто на выходе")
	}
}

func TestOutputChainFreesOnlyLoopbackOfficeAndTunnel(t *testing.T) {
	chain := outputChain(t, blackPlan())

	first := ""
	for _, ln := range strings.Split(chain, "\n")[2:] {
		if ln = strings.TrimSpace(ln); strings.HasSuffix(ln, " accept") || strings.Contains(ln, " drop") {
			first = ln
			break
		}
	}
	if first != `oifname { "ens4", "lo", "wg-vpn0" } accept` {
		t.Errorf("свободно уходить может только петля, офис и канал, а не %q", first)
	}
	if strings.Contains(chain, "oifname !=") {
		t.Error("охрана «всё, кроме карты провайдера» зависит от имени WAN — ровно та дыра, что закрыта")
	}
}

func TestOutputChainDoesNotDependOnWANName(t *testing.T) {
	stale := blackPlan()
	current := blackPlan()
	current.WANs = []string{"ppp0"}
	if outputChain(t, stale) != outputChain(t, current) {
		t.Error("цепочка выхода зависит от имени WAN — устаревший план откроет новый интерфейс")
	}
}

func TestNoOutputChainInWhiteMode(t *testing.T) {
	p := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "10.0.0.1/24"}}}
	if strings.Contains(string(p.Generate()), "chain output") {
		t.Error("в прямом режиме цепочка выхода не нужна: она ничего не защищает, но может мешать")
	}
}

func TestNoOutputChainWithoutEndpoint(t *testing.T) {

	p := blackPlan()
	p.Tunnel.Endpoint = ""
	if strings.Contains(string(p.Generate()), "chain output") {
		t.Error("без адреса сервера цепочка выхода запирает канал — её быть не должно")
	}
}

func TestOutputChainValidatesAddresses(t *testing.T) {
	cases := map[string]func(*FirewallTunnel){
		"адрес сервера не адрес": func(t *FirewallTunnel) { t.Endpoint = "vpn.example.net" },
		"порт вне границ":        func(t *FirewallTunnel) { t.EndpointPort = 70000 },
		"метка вне границ":       func(t *FirewallTunnel) { t.Mark = -1 },
	}
	for name, break_ := range cases {
		p := blackPlan()
		break_(p.Tunnel)
		if err := p.Validate(map[string]bool{"ens3": true, "ens4": true}); err == nil {
			t.Errorf("%s: план принят, а должен быть отвергнут", name)
		}
	}
}

func TestOutputChainIsDeterministic(t *testing.T) {
	a := blackPlan()
	b := blackPlan()
	if string(a.Generate()) != string(b.Generate()) {
		t.Error("один и тот же план даёт разный рулсет — идемпотентность сломана")
	}
}
