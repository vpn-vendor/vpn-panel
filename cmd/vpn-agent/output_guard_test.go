package main

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

func TestMarkSocketAlwaysMarks(t *testing.T) {
	if markSocket(0) == nil {
		t.Fatal("при мёртвом канале метка не ставится — цепочка выхода запрёт шлюз навсегда")
	}
	if markSocket(wggen.DefaultFwmark) == nil {
		t.Fatal("метка живого канала не ставится")
	}
}

func TestCurrentFwmarkNeverZero(t *testing.T) {

	if got := currentTunnelFwmark(); got <= 0 {
		t.Fatalf("метка = %d; ноль означает «служебный пакет не пройдёт цепочку выхода»", got)
	}
}

func TestPatchOutputChainFillsAllowList(t *testing.T) {
	v := &vpnApplier{}
	st := &vpnState{
		EndpointIP:   "203.0.113.7",
		EndpointPort: 51820,
	}
	st.Black.Firewall.Tunnel = &nftgen.FirewallTunnel{Iface: wggen.TunnelIface}
	v.patchOutputChain(st)
	got := st.Black.Firewall.Tunnel

	if got.Endpoint != "203.0.113.7" || got.EndpointPort != 51820 {
		t.Errorf("адрес сервера не попал в список разрешений: %+v", got)
	}
	if got.Mark <= 0 {
		t.Error("служебная метка не заполнена: без неё служебный запрос не пройдёт цепочку выхода")
	}
}

func TestPatchOutputChainSkipsWhiteMode(t *testing.T) {
	v := &vpnApplier{}
	st := &vpnState{EndpointIP: "203.0.113.7"}
	v.patchOutputChain(st)
	if st.Black.Firewall.Tunnel != nil {
		t.Error("в белом режиме цепочка выхода не создаётся")
	}
}

func TestParseLeakDropsSumsOurRulesOnly(t *testing.T) {
	out := []byte(`{"nftables":[
      {"metainfo":{"version":"1.0.9"}},
      {"rule":{"chain":"output","comment":"` + nftgen.LeakDropComment + `","expr":[{"counter":{"packets":7,"bytes":500}},{"drop":null}]}},
      {"rule":{"chain":"output","comment":"` + nftgen.LeakDropComment + `","expr":[{"counter":{"packets":5,"bytes":300}},{"drop":null}]}},
      {"rule":{"chain":"output","comment":"чужое правило","expr":[{"counter":{"packets":100,"bytes":1}}]}},
      {"rule":{"chain":"output","expr":[{"accept":null}]}}
    ]}`)
	if got := parseLeakDrops(out); got != 12 {
		t.Fatalf("поймано попыток = %d, ожидалось 12", got)
	}
}

func TestParseLeakDropsSurvivesGarbage(t *testing.T) {
	for _, in := range []string{"", "не json", "{}", `{"nftables":[]}`} {
		if got := parseLeakDrops([]byte(in)); got != 0 {
			t.Errorf("на входе %q счётчик = %d, ожидался 0", in, got)
		}
	}
}

func TestStartingResolverIsOurs(t *testing.T) {
	ours := []string{"active", "activating", "reloading", "refreshing"}
	foreign := []string{"inactive", "failed", "deactivating", "unknown", ""}
	for _, s := range ours {
		if !isOurServiceState(s) {
			t.Errorf("состояние %q сочтено чужой службой — восстановление оборвётся на ровном месте", s)
		}
	}
	for _, s := range foreign {
		if isOurServiceState(s) {
			t.Errorf("состояние %q сочтено нашим — чужая служба на порту 53 останется незамеченной", s)
		}
	}
}

func TestIfaceExistsTellsTruth(t *testing.T) {
	if !ifaceExists("lo") {
		t.Error("петля обязана существовать всегда")
	}
	if ifaceExists("нет-такого-интерфейса") {
		t.Error("несуществующий интерфейс объявлен существующим")
	}
}

func TestLivenessProbeNameIsUnique(t *testing.T) {
	first, second := uncacheableProbeName(), uncacheableProbeName()
	if first == second {
		t.Fatal("имя пробы повторяется — его закэширует наш же резолвер")
	}
	for _, name := range []string{first, second} {
		if !strings.HasSuffix(name, "."+externalProbeZone) {
			t.Errorf("имя пробы вне известной зоны: %q", name)
		}
		if len(name) <= len(externalProbeZone)+1 {
			t.Errorf("у имени пробы нет уникальной части: %q", name)
		}
	}
}

func TestLeakWatchCountedApartFromDrops(t *testing.T) {
	out := []byte(`{"nftables":[
      {"rule":{"chain":"leak_watch","comment":"` + nftgen.LeakWatchComment + `","expr":[{"counter":{"packets":3,"bytes":180}}]}},
      {"rule":{"chain":"output","comment":"` + nftgen.LeakDropComment + `","expr":[{"counter":{"packets":9,"bytes":500}},{"drop":null}]}}
    ]}`)
	if got := parseCounter(out, nftgen.LeakWatchComment); got != 3 {
		t.Fatalf("сигнализация насчитала %d, ожидалось 3", got)
	}
	if got := parseLeakDrops(out); got != 9 {
		t.Fatalf("сброс насчитал %d, ожидалось 9", got)
	}
}
