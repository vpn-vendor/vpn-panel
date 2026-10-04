package wggen

import "testing"

func TestParseHandshakesAndTransfer(t *testing.T) {
	hs := ParseHandshakes([]byte(pubKey + "\t1789123456\n"))
	if hs[pubKey] != 1789123456 {
		t.Fatalf("рукопожатие разобрано неверно: %v", hs)
	}
	tr := ParseTransfer([]byte(pubKey + "\t123456\t7890\n"))
	if tr[pubKey] != [2]int64{123456, 7890} {
		t.Fatalf("счётчики разобраны неверно: %v", tr)
	}
	ep := ParseEndpoints([]byte(pubKey + "\t203.0.113.7:51820\n"))
	if ep[pubKey] != "203.0.113.7:51820" {
		t.Fatalf("адрес сервера разобран неверно: %v", ep)
	}

	if len(ParseEndpoints([]byte(pubKey+"\t(none)\n"))) != 0 {
		t.Fatal("«(none)» не должно попадать в состояние")
	}
	states := PeerStates([]byte(pubKey+"\t1789123456\n"), []byte(pubKey+"\t10\t20\n"),
		[]byte(pubKey+"\t203.0.113.7:51820\n"))
	if len(states) != 1 || states[0].RxBytes != 10 || states[0].TxBytes != 20 ||
		states[0].Endpoint != "203.0.113.7:51820" {
		t.Fatalf("сводное состояние собрано неверно: %+v", states)
	}
}

func TestParseFwmark(t *testing.T) {
	cases := map[string]int{
		"0xca6c\n": 51820,
		"51820\n":  51820,
		"off\n":    0,
		"":         0,
		"мусор":    0,
	}
	for in, want := range cases {
		if got := ParseFwmark([]byte(in)); got != want {
			t.Errorf("ParseFwmark(%q) = %d, ожидалось %d", in, got, want)
		}
	}
}

func TestParseGarbageIsSafe(t *testing.T) {
	garbage := []byte("не табличный вывод\n\n\t\t\nключ\tне-число\n")
	if len(ParseHandshakes(garbage)) != 0 || len(ParseTransfer(garbage)) != 0 {
		t.Fatal("мусорный вывод обязан разбираться в пустоту, а не в фальшивое состояние")
	}
}
