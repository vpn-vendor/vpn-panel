package change

import (
	"errors"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type sec struct {
	N    int               `json:"n"`
	Old  string            `json:"old"`
	Tags map[string]string `json:"tags"`
}

func validate(s sec) fielderr.List {
	var errs fielderr.List
	if s.N > 10 {
		errs.Add("n", "больше 10")
	}
	if s.Old == "плохо" {
		errs.Add("old", "старое несоответствие")
	}
	return errs
}

func section(cur sec, applied *[2]sec) Section[sec] {
	return Section[sec]{
		Read:     func() (sec, error) { return cur, nil },
		Validate: validate,
		Apply:    func(c, w sec) error { applied[0], applied[1] = c, w; return nil },
	}
}

func TestRatchet(t *testing.T) {
	var got [2]sec
	cur := sec{N: 1, Old: "плохо", Tags: map[string]string{"a": "1"}}
	if _, err := Apply(section(cur, &got), func(s *sec) error { s.N = 5; return nil }); err != nil {
		t.Fatalf("старое несоответствие заблокировало изменение: %v", err)
	}
	_, err := Apply(section(cur, &got), func(s *sec) error { s.N = 11; return nil })
	var rej *Rejected
	if !errors.As(err, &rej) || !rej.Errors.Has("n") || rej.Errors.Has("old") {
		t.Fatalf("новая ошибка не отвергнута или старая названа новой: %v", err)
	}
}

func TestWantIsDeepCopy(t *testing.T) {
	var got [2]sec
	cur := sec{Tags: map[string]string{"a": "1"}}
	if _, err := Apply(section(cur, &got), func(s *sec) error { s.Tags["a"] = "2"; return nil }); err != nil {
		t.Fatal(err)
	}
	if got[0].Tags["a"] != "1" || got[1].Tags["a"] != "2" {
		t.Fatalf("текущее %v, желаемое %v — разница пропала бы", got[0].Tags, got[1].Tags)
	}
}

func TestEditErrorStops(t *testing.T) {
	applied := false
	s := Section[sec]{
		Read:     func() (sec, error) { return sec{}, nil },
		Validate: validate,
		Apply:    func(sec, sec) error { applied = true; return nil },
	}
	want := errors.New("не число")
	if _, err := Apply(s, func(*sec) error { return want }); !errors.Is(err, want) {
		t.Fatalf("ошибка ввода потеряна: %v", err)
	}
	if applied {
		t.Fatal("применение вызвано после ошибки ввода")
	}
}

func TestRows(t *testing.T) {
	type row struct{ K, V string }
	cur := []row{{"a", "1"}, {"b", "1"}, {"c", "1"}}
	want := []row{{"a", "1"}, {"b", "2"}, {"d", "1"}}
	add, chg, del := Rows(cur, want, func(r row) string { return r.K })
	if len(add) != 1 || add[0].K != "d" || len(chg) != 1 || chg[0] != (row{"b", "2"}) || len(del) != 1 || del[0].K != "c" {
		t.Fatalf("добавлено %v, изменено %v, убрано %v", add, chg, del)
	}
}
