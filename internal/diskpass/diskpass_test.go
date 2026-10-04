package diskpass

import (
	"strings"
	"testing"
)

func policy(t *testing.T) *Policy {
	t.Helper()
	p, err := NewPolicy(strings.NewReader("# частые\nPassword2026!\n  iloveyou1234  \n\n"), "office-gw", "gw")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheck(t *testing.T) {
	p := policy(t)
	cases := []struct {
		pw   string
		want Reason
	}{
		{"zelenyj-chajnik-7", OK},
		{"Tri kota na kryshe", OK},
		{"зелёный-чайник-7", NotLatin},
		{"zelenyj\tchajnik", NotLatin},
		{"short-pass1", Short},
		{"aaaaaaaaaaaaaa", Trivial},
		{"qwertyuiopas", Trivial},
		{"123456789012", Trivial},
		{"sapoiuytrewq", Trivial},
		{"PASSWORD2026!", Common},
		{"iloveyou1234", Common},
		{"my-office-gw-2026", Context},
		{"gwgwgwgwgwgw-x", OK},
	}
	for _, c := range cases {
		if got := p.Check(c.pw); got != c.want {
			t.Errorf("Check(%q) = %q, want %q", c.pw, got, c.want)
		}
	}
}

func TestLatinCheckedBeforeLength(t *testing.T) {
	if got := policy(t).Check("пароль"); got != NotLatin {
		t.Fatalf("короткий кириллический пароль: %q, нужно сначала про раскладку", got)
	}
}

func TestShortContextWordIgnored(t *testing.T) {
	p, err := NewPolicy(strings.NewReader(""), "gw")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Check("big-gwen-garden"); got != OK {
		t.Fatalf("слово шлюза короче порога не проверяется: %q", got)
	}
}

func TestBuiltinList(t *testing.T) {
	p, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"Password1234", "iloveyou1234", "qwertyuiop123", "1q2w3e4r5t6y"} {
		if got := p.Check(pw); got != Common {
			t.Errorf("Check(%q) = %q: длинный частый пароль обязан быть отвергнут списком", pw, got)
		}
	}
	if got := p.Check("zelenyj-chajnik-na-okne-7"); got != OK {
		t.Errorf("обычная фраза отвергнута: %q", got)
	}
}
