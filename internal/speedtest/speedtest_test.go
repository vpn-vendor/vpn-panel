package speedtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKbitPerSec(t *testing.T) {

	if got := kbitPerSec(1_000_000, time.Second); got != 8000 {
		t.Fatalf("kbitPerSec(1MB,1s) = %d, want 8000", got)
	}
	if got := kbitPerSec(0, time.Second); got != 0 {
		t.Fatalf("zero bytes: %d", got)
	}

	if got := kbitPerSec(1000, 0); got != 8000 {
		t.Fatalf("sub-ms floor: %d, want 8000", got)
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []SourceResult
		want int
	}{
		{[]SourceResult{{Kbit: 100}, {Kbit: 300}, {Kbit: 200}}, 200},
		{[]SourceResult{{Kbit: 100}, {Kbit: 0}, {Kbit: 300}}, 200},
		{[]SourceResult{{Kbit: 100}}, 100},
		{[]SourceResult{{Kbit: 0}, {Kbit: 0}}, 0},
		{nil, 0},
	}
	for i, c := range cases {
		if got := median(c.in); got != c.want {
			t.Errorf("case %d: median = %d, want %d", i, got, c.want)
		}
	}
}

func TestDivergent(t *testing.T) {
	if divergent([]SourceResult{{Kbit: 100_000}, {Kbit: 105_000}}) {
		t.Fatal("5% расхождение не должно помечаться")
	}
	if !divergent([]SourceResult{{Kbit: 100_000}, {Kbit: 130_000}}) {
		t.Fatal("30% расхождение обязано помечаться")
	}
	if divergent([]SourceResult{{Kbit: 0}, {Kbit: 0}}) {
		t.Fatal("пустые источники не расходятся")
	}

	if divergent([]SourceResult{{Kbit: 0}, {Kbit: 100_000}, {Kbit: 101_000}}) {
		t.Fatal("ноль недоступного источника не должен давать ложное расхождение")
	}
}

func TestMeasureAgainstLocalServer(t *testing.T) {
	payload := make([]byte, 512*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := &Client{
		HTTP:          srv.Client(),
		Sources:       []Source{{Name: "локальный", URL: srv.URL}},
		Upload:        Source{Name: "локальный", URL: srv.URL},
		PerSourceTime: 500 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Measure(ctx)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if res.DownKbit <= 0 || res.UpKbit <= 0 {
		t.Fatalf("ожидались ненулевые скорости, получено down=%d up=%d", res.DownKbit, res.UpKbit)
	}
	if len(res.Down) != 1 || res.Down[0].Kbit != res.DownKbit {
		t.Fatalf("медиана одного источника обязана равняться ему: %+v", res)
	}
}

func TestMeasureAllSourcesDead(t *testing.T) {
	c := &Client{
		HTTP:          &http.Client{Timeout: time.Second},
		Sources:       []Source{{Name: "мёртвый", URL: "http://127.0.0.1:1/x"}},
		Upload:        Source{Name: "мёртвый", URL: "http://127.0.0.1:1/x"},
		PerSourceTime: 500 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Measure(ctx); err == nil {
		t.Fatal("все источники мертвы — ожидалась ошибка")
	}
}
