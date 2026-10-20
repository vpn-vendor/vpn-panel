package nftgen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

func allCaps() Caps {
	var c Caps
	for _, o := range Options {
		o.Enable(&c)
	}
	return c
}

func TestOptionIDsAreStable(t *testing.T) {
	want := []string{"nft.forward_witness", "nft.dhcp_watch"}
	if got := hostcaps.IDs(Options); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("идентификаторы возможностей %v, ждали %v", got, want)
	}
}

func TestOptionsCoverCaps(t *testing.T) {
	base := ProbeRuleset(Caps{})
	for _, o := range Options {
		var c Caps
		o.Enable(&c)
		if c == (Caps{}) {
			t.Errorf("возможность %s ничего не включает", o.ID)
		}
		if bytes.Equal(ProbeRuleset(c), base) {
			t.Errorf("возможность %s не меняет пробный набор", o.ID)
		}
	}
	if zero := hostcaps.ZeroFields(allCaps()); len(zero) > 0 {
		t.Fatalf("флаги %v не объявлены возможностями", zero)
	}
}

func TestOptionsHaveTexts(t *testing.T) {
	for _, o := range Options {
		if o.Title == "" || o.Missing == "" {
			t.Errorf("у возможности %s нет текста", o.ID)
		}
		if len(o.Consumers) == 0 {
			t.Errorf("у возможности %s нет раздела-потребителя", o.ID)
		}
	}
}

func TestProbeRulesetBaseHasNoOptions(t *testing.T) {
	p := ProbePlan()
	base := ProbeRuleset(Caps{})
	if !bytes.Equal(base, p.Generate(Caps{})) {
		t.Fatal("пробный набор без флагов разошёлся с пробным планом")
	}
	for _, bad := range []string{"witness", "seen_", DHCPWatchTable} {
		if bytes.Contains(base, []byte(bad)) {
			t.Errorf("в базовой пробе есть необязательное %q", bad)
		}
	}
	w := ProbeDHCPWatch()
	if zero := hostcaps.ZeroFields(w); len(zero) > 0 {
		t.Fatalf("пробная таблица наблюдения не задействует поля %v", zero)
	}
	if err := w.Validate(); err != nil {
		t.Fatalf("пробная таблица наблюдения не проходит проверку: %v", err)
	}
}

func TestProbeOptionsIndependent(t *testing.T) {
	const spoil = "vp-probe-unknown-statement"
	for _, c := range []struct {
		name, reject        string
		base, witness, dhcp hostcaps.Answer
	}{
		{"всё принято", "", hostcaps.Yes, hostcaps.Yes, hostcaps.Yes},
		{"нет именованных счётчиков", "counter name", hostcaps.Yes, hostcaps.No, hostcaps.Yes},
		{"нет наблюдения", "ether_addr", hostcaps.Yes, hostcaps.Yes, hostcaps.No},
		{"база не принята", "masquerade", hostcaps.No, hostcaps.Unknown, hostcaps.Unknown},
	} {
		facts := hostcaps.Probe(hostcaps.Program[Caps]{
			Render: func(f Caps) ([]byte, error) { return ProbeRuleset(f), nil },
			Check: func(b []byte) error {
				if bytes.Contains(b, []byte(spoil)) || (c.reject != "" && bytes.Contains(b, []byte(c.reject))) {
					return &hostcaps.Rejected{Detail: "проба"}
				}
				return nil
			},
			Spoil:     func(b []byte) []byte { return append(append([]byte(nil), b...), spoil+"\n"...) },
			Base:      "nft.ruleset",
			BaseClass: hostcaps.ClassGuard,
			Options:   Options,
		})
		got := map[string]hostcaps.Answer{}
		for _, f := range facts {
			got[f.ID] = f.Answer
		}
		want := map[string]hostcaps.Answer{"nft.ruleset": c.base, "nft.forward_witness": c.witness, "nft.dhcp_watch": c.dhcp}
		for id, a := range want {
			if got[id] != a {
				t.Errorf("%s: %s = %s, ждали %s", c.name, id, got[id], a)
			}
		}
	}
}
