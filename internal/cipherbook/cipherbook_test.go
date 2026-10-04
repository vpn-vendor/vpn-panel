package cipherbook

import (
	"os"
	"strings"
	"testing"
)

func TestEveryDaemonCipherIsClassified(t *testing.T) {
	raw, err := os.ReadFile("testdata/show-ciphers-2.7.0.txt")
	if err != nil {
		t.Fatal(err)
	}
	deprecated := false
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "DEPRECATED" {
			deprecated = true
			continue
		}
		n++
		e := Lookup(line)
		if e.Family == FamilyUnknown || e.Fitness == FitnessUnknown {
			t.Errorf("%s: словарь не знает семейства или пригодности", line)
		}
		if deprecated && e.Fitness != Refuse {
			t.Errorf("%s: демон пометил «не используйте», словарь обязан отказывать", line)
		}
		if !deprecated && e.Fitness == Refuse {
			t.Errorf("%s: демон принимает, словарь отказывает без причины", line)
		}
	}
	if n < 60 {
		t.Fatalf("список демона неполон: %d имён", n)
	}
}

func TestFitnessByFamily(t *testing.T) {
	cases := map[string]Fitness{
		"AES-128-GCM": Fit, "aes-256-gcm": Fit, "CHACHA20-POLY1305": Fit,
		"ARIA-256-GCM": Unfit, "SM4-GCM": Unfit,
		"AES-256-CBC": Unfit, "AES-128-CFB": Unfit, "CAMELLIA-256-OFB": Unfit,
		"DES-EDE3-CBC": Refuse, "BF-CBC": Refuse, "none": Refuse, "RC2-40-CBC": Refuse,
		"FUTURE-512-XYZ": FitnessUnknown,
	}
	for name, want := range cases {
		if got := Lookup(name).Fitness; got != want {
			t.Errorf("%s: пригодность %v, ожидали %v", name, got, want)
		}
	}
	if !Lookup("AES-256-GCM").Kernel || Lookup("AES-256-CBC").Kernel || Lookup("ARIA-128-GCM").Kernel {
		t.Fatal("плоскость данных в ядре определена неверно")
	}
}

func TestClassifyLists(t *testing.T) {
	if v := Classify(nil, ""); v.Fitness != Fit || v.Mixed {
		t.Fatalf("умолчания демона годятся: %+v", v)
	}
	if v := Classify(SplitList("AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"), "SHA256"); v.Fitness != Fit || v.Mixed {
		t.Fatalf("наш файл: %+v", v)
	}
	if v := Classify([]string{"AES-256-CBC"}, "SHA512"); v.Fitness != Unfit {
		t.Fatalf("CBC один: %+v", v)
	}
	if v := Classify(SplitList("AES-256-GCM:AES-256-CBC"), ""); v.Fitness != Fit || !v.Mixed {
		t.Fatalf("смешанный список — годится с оговоркой: %+v", v)
	}
	if v := Classify([]string{"AES-256-GCM"}, "MD5"); v.Fitness != Refuse || len(v.Refused) != 1 {
		t.Fatalf("MD5: %+v", v)
	}
	if v := Classify([]string{"BF-CBC"}, ""); v.Fitness != Refuse || v.Refused[0] != "BF-CBC" {
		t.Fatalf("Blowfish: %+v", v)
	}
	if v := Classify([]string{"FUTURE-512-XYZ"}, ""); v.Fitness != Unfit || len(v.Unknown) != 1 {
		t.Fatalf("неизвестное — не годится и названо: %+v", v)
	}
	if !UsesAES(nil) || !UsesAES([]string{"aes-128-gcm"}) || UsesAES([]string{"CHACHA20-POLY1305"}) {
		t.Fatal("признак AES")
	}
}

func TestOverhead(t *testing.T) {
	cases := []struct {
		names []string
		auth  string
		ipv6  bool
		want  int
	}{
		{nil, "", false, 52},
		{[]string{"AES-128-GCM"}, "SHA256", false, 52},
		{[]string{"CHACHA20-POLY1305"}, "SHA512", true, 72},
		{[]string{"AES-256-CBC"}, "SHA256", false, 100},
		{[]string{"AES-256-CBC"}, "SHA512", false, 132},
		{[]string{"AES-256-CBC"}, "", false, 88},
		{[]string{"AES-256-CFB"}, "SHA1", false, 72},
		{SplitList("AES-256-GCM:AES-256-CBC"), "SHA512", false, 132},
		{[]string{"FUTURE-512-XYZ"}, "", false, 132},
	}
	for _, c := range cases {
		if got := Overhead(c.names, c.auth, c.ipv6); got != c.want {
			t.Errorf("%v/%s ipv6=%v: %d, ожидали %d", c.names, c.auth, c.ipv6, got, c.want)
		}
	}
	if OverheadAEAD4 != 52 {
		t.Fatal("константа AEAD расходится с захватом")
	}
}
