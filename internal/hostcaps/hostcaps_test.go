package hostcaps

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type flags struct{ A, B bool }

var testOptions = []Option[flags]{
	{ID: "x.a", Consumers: []string{"dhcp"}, Enable: func(c *flags) { c.A = true }},
	{ID: "x.b", Consumers: []string{"vpn"}, Enable: func(c *flags) { c.B = true }},
}

func render(c flags) ([]byte, error) {
	s := "base"
	if c.A {
		s += " a"
	}
	if c.B {
		s += " b"
	}
	return []byte(s), nil
}

func spoil(b []byte) []byte { return append(append([]byte(nil), b...), " bad"...) }

func program(known ...string) Program[flags] {
	return Program[flags]{
		Render: render,
		Spoil:  spoil,
		Check: func(b []byte) error {
			for _, w := range strings.Fields(string(b)) {
				ok := false
				for _, k := range known {
					ok = ok || w == k
				}
				if !ok {
					return &Rejected{Detail: w}
				}
			}
			return nil
		},
		Base:      "x.base",
		BaseClass: ClassGuard,
		Options:   testOptions,
	}
}

func answers(facts []Fact) map[string]string {
	m := map[string]string{}
	for _, f := range facts {
		m[f.ID] = string(f.Answer) + "/" + f.How
	}
	return m
}

func TestProbeAnswersEachOptionSeparately(t *testing.T) {
	got := answers(Probe(program("base", "a")))
	want := map[string]string{"x.base": "yes/check", "x.a": "yes/check", "x.b": "no/check"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ответы %v, ждали %v", got, want)
	}
}

func TestProbeDistrustsCheckThatAcceptsSpoiled(t *testing.T) {
	got := answers(Probe(program("base", "a", "b", "bad")))
	for id, a := range got {
		if a != "unknown/control" {
			t.Errorf("%s: %s, ждали unknown/control", id, a)
		}
	}
}

func TestProbeBaseRejectedLeavesOptionsUnknown(t *testing.T) {
	got := answers(Probe(program("a", "b")))
	want := map[string]string{"x.base": "no/check", "x.a": "unknown/base", "x.b": "unknown/base"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ответы %v, ждали %v", got, want)
	}
}

func TestProbeCheckThatCannotRunIsUnknown(t *testing.T) {
	p := program("base", "a", "b")
	p.Check = func([]byte) error { return errors.New("программы нет") }
	for id, a := range answers(Probe(p)) {
		if a != "unknown/failed" {
			t.Errorf("%s: %s, ждали unknown/failed", id, a)
		}
	}
}

func TestProbeWithoutBaseFactPublishesOnlyOptions(t *testing.T) {
	p := program("base", "a", "b")
	p.Base = ""
	facts := Probe(p)
	if len(facts) != 2 || facts[0].ID != "x.a" || facts[0].Class != ClassFeature {
		t.Fatalf("факты %+v", facts)
	}
}

func TestCapsTakeOnlyYes(t *testing.T) {
	s := Snapshot{Facts: []Fact{{ID: "x.a", Answer: Yes}, {ID: "x.b", Answer: Unknown}}}
	if got := Caps(s, testOptions); got != (flags{A: true}) {
		t.Fatalf("флаги %+v", got)
	}
	if got := Caps(Snapshot{}, testOptions); got != (flags{}) {
		t.Fatalf("пустой паспорт дал флаги %+v", got)
	}
}

func TestDigestsIgnoreOrder(t *testing.T) {
	a := []Fact{{ID: "x.a", Answer: Yes, Consumers: []string{"dhcp"}}, {ID: "x.b", Answer: No, Consumers: []string{"vpn"}}}
	b := []Fact{a[1], a[0]}
	if FactsDigest(a) != FactsDigest(b) {
		t.Fatal("отпечаток фактов зависит от порядка")
	}
	changed := []Fact{a[0], {ID: "x.b", Answer: Yes, Consumers: []string{"vpn"}}}
	if FactsDigest(a) == FactsDigest(changed) {
		t.Fatal("отпечаток не заметил смену ответа")
	}
	if SectionDigest(a, "dhcp") != SectionDigest(changed, "dhcp") {
		t.Fatal("смена чужого факта сменила отпечаток раздела")
	}
	if SectionDigest(a, "vpn") == SectionDigest(changed, "vpn") {
		t.Fatal("смена своего факта не сменила отпечаток раздела")
	}
	v1 := map[string]string{"kernel": "5.15", "openvpn": "2.5"}
	v2 := map[string]string{"openvpn": "2.5", "kernel": "5.15"}
	if InputsDigest(v1, []string{"x.a", "x.b"}) != InputsDigest(v2, []string{"x.b", "x.a"}) {
		t.Fatal("ключ кэша зависит от порядка")
	}
	if InputsDigest(v1, []string{"x.a"}) == InputsDigest(v1, []string{"x.a", "x.b"}) {
		t.Fatal("новый факт не сменил ключ кэша")
	}
}

func TestUnsureAndValue(t *testing.T) {
	s := Snapshot{Facts: []Fact{{ID: "os.codename", Answer: Yes, Value: "jammy"}, {ID: "x.a", Answer: No}}}
	if s.Unsure() || s.Value("os.codename") != "jammy" || s.Value("x.a") != "" {
		t.Fatalf("снимок %+v", s)
	}
	s.Facts = append(s.Facts, Fact{ID: "x.b", Answer: Unknown})
	if !s.Unsure() {
		t.Fatal("неизвестный факт не замечен")
	}
	if s.Answer("нет-такого") != Unknown {
		t.Fatal("отсутствующий факт обязан быть неизвестным")
	}
}

func TestZeroFieldsFindsNested(t *testing.T) {
	type inner struct{ N int }
	type plan struct {
		Name  string
		Items []inner
		Ptr   *inner
		Flags flags
		Skip  bool
	}
	got := ZeroFields(plan{Name: "x", Items: []inner{{}}, Flags: flags{A: true}}, "Skip")
	want := []string{"Flags.B", "Items[0].N", "Ptr"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("пустые поля %v, ждали %v", got, want)
	}
}

func TestDefectsCarryEvidence(t *testing.T) {
	for _, d := range Defects {
		if d.ID == "" || d.Package == "" || d.Versions == "" || d.Evidence == "" || d.Until == "" {
			t.Errorf("дефект %+v без доказательства или условия снятия", d)
		}
	}
}
