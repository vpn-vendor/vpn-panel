package admission

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDeriveFrozen(t *testing.T) {
	one := Derive(1)
	if one.Ceiling != 8 || one.Reserve != 2 || one.ShedCeiling != 4 || one.LoopbackCeiling != 2 || one.QueueCeiling != 32 {
		t.Fatalf("одно ядро: %+v", one)
	}
	four := Derive(4)
	if four.Ceiling != 32 || four.Reserve != 8 || four.ShedCeiling != 16 || four.LoopbackCeiling != 8 || four.QueueCeiling != 128 {
		t.Fatalf("четыре ядра: %+v", four)
	}
	if Derive(0).Ceiling != 8 {
		t.Fatal("ноль ядер должен считаться как одно")
	}
	if one.WaitTarget != 100*time.Millisecond || one.WaitInterval != time.Second ||
		one.OrdinaryWait != 5*time.Second || one.CriticalWait != 30*time.Second || one.RetryAfter != 2*time.Second {
		t.Fatalf("сроки изменены: %+v", one)
	}
}

func TestClassifyLongestPrefixWins(t *testing.T) {
	rules := []Rule{
		{Prefix: "/", Class: Ordinary},
		{Prefix: "/qos", Class: Ordinary},
		{Method: "GET", Prefix: "/qos/speedtest/status", Class: Sheddable},
		{Method: "POST", Prefix: "/qos/apply", Class: Critical},
		{Prefix: "/login", Class: Critical},
	}
	cases := []struct {
		method, path string
		want         Class
	}{
		{"GET", "/qos", Ordinary},
		{"GET", "/qos/speedtest/status", Sheddable},
		{"POST", "/qos/apply", Critical},
		{"GET", "/qos/apply", Ordinary},
		{"GET", "/loginx", Ordinary},
		{"POST", "/login", Critical},
		{"GET", "/anything", Ordinary},
	}
	for _, c := range cases {
		if got, _ := Classify(rules, c.method, c.path); got != c.want {
			t.Errorf("%s %s: %v, ожидалось %v", c.method, c.path, got, c.want)
		}
	}
	if _, found := Classify(rules[1:], "GET", "/other"); found {
		t.Fatal("путь без правила не должен считаться найденным")
	}
}

type blocking struct {
	entered chan struct{}
	release chan struct{}
}

func newBlocking() *blocking {
	return &blocking{entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (b *blocking) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	b.entered <- struct{}{}
	<-b.release
	w.WriteHeader(http.StatusOK)
}

func smallPolicy() Policy {
	p := Derive(1)
	p.Ceiling, p.Reserve, p.ShedCeiling, p.LoopbackCeiling, p.QueueCeiling = 4, 2, 1, 1, 4
	p.OrdinaryWait, p.CriticalWait = 50*time.Millisecond, 50*time.Millisecond
	return p
}

var testRules = []Rule{
	{Prefix: "/", Class: Ordinary},
	{Prefix: "/shed", Class: Sheddable},
	{Prefix: "/crit", Class: Critical},
}

func do(g *Gate, method, path, remote string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	g.ServeHTTP(rec, req)
	return rec
}

func doAsync(g *Gate, wg *sync.WaitGroup, method, path, remote string, out *[]int, mu *sync.Mutex) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		code := do(g, method, path, remote).Code
		mu.Lock()
		*out = append(*out, code)
		mu.Unlock()
	}()
}

const lan = "192.168.77.10:5000"

func TestReserveOnlyForTrustedCritical(t *testing.T) {
	h := newBlocking()
	trusted := false
	g := New(h, testRules, smallPolicy(), func(*http.Request) bool { return trusted }, nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var codes []int

	doAsync(g, &wg, "GET", "/a", lan, &codes, &mu)
	doAsync(g, &wg, "GET", "/b", lan, &codes, &mu)
	<-h.entered
	<-h.entered

	if code := do(g, "GET", "/c", lan).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("обычный при занятых слотах: %d", code)
	}
	if code := do(g, "POST", "/crit", lan).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("критичный без подлинности получил резерв: %d", code)
	}
	trusted = true
	doAsync(g, &wg, "POST", "/crit", lan, &codes, &mu)
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("критичный с подлинностью не вошёл через резерв")
	}
	snap := g.Snapshot()
	if snap.Inflight != 3 || snap.Shed[Ordinary] != 1 || snap.Shed[Critical] != 1 {
		t.Fatalf("снимок: %+v", snap)
	}
	close(h.release)
	wg.Wait()
}

func TestSheddableRefusedUnderSignal(t *testing.T) {
	hot := false
	sig := []Signal{{Name: "давление", Hot: func() (bool, string) { return hot, "ядро занято" }}}
	g := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }),
		testRules, smallPolicy(), nil, sig, nil)
	if code := do(g, "GET", "/shed", lan).Code; code != 200 {
		t.Fatalf("сбрасываемый в покое: %d", code)
	}
	hot = true
	g.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if code := do(g, "GET", "/shed", lan).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("сбрасываемый под сигналом: %d", code)
	}
	if code := do(g, "GET", "/page", lan).Code; code != 200 {
		t.Fatalf("обычный под сигналом при свободной ёмкости: %d", code)
	}
	snap := g.Snapshot()
	if !snap.Overloaded || !snap.SignalHot || snap.SignalName != "давление" || snap.Shed[Sheddable] != 1 {
		t.Fatalf("снимок: %+v", snap)
	}
}

func TestShedBulkhead(t *testing.T) {
	h := newBlocking()
	g := New(h, testRules, smallPolicy(), nil, nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var codes []int
	doAsync(g, &wg, "GET", "/shed", lan, &codes, &mu)
	<-h.entered
	if code := do(g, "GET", "/shed", lan).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("второй сбрасываемый прошёл сквозь перегородку: %d", code)
	}
	doAsync(g, &wg, "GET", "/page", "192.168.77.11:1", &codes, &mu)
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("обычный не должен страдать от перегородки сбрасываемых")
	}
	close(h.release)
	wg.Wait()
}

func TestLoopbackLaneIsSeparate(t *testing.T) {
	h := newBlocking()
	g := New(h, testRules, smallPolicy(), func(*http.Request) bool { return true }, nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var codes []int
	for i := 0; i < 4; i++ {
		doAsync(g, &wg, "POST", "/crit", lan, &codes, &mu)
		<-h.entered
	}
	if code := do(g, "POST", "/crit", lan).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("сеть при полной ёмкости: %d", code)
	}
	doAsync(g, &wg, "GET", "/page", "127.0.0.1:4000", &codes, &mu)
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("петля не вошла при занятой сети")
	}
	if code := do(g, "GET", "/page", "[::1]:4000").Code; code != http.StatusServiceUnavailable {
		t.Fatalf("петля сверх своей ёмкости: %d", code)
	}
	close(h.release)
	wg.Wait()
}

func TestCriticalWaiterServedFirst(t *testing.T) {
	h := newBlocking()
	p := smallPolicy()
	p.Ceiling, p.Reserve = 1, 0
	p.OrdinaryWait, p.CriticalWait = time.Second, time.Second
	g := New(h, testRules, p, nil, nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var order []string
	first := make(chan struct{})
	wg.Add(1)
	go func() { defer wg.Done(); do(g, "GET", "/hold", lan) }()
	<-h.entered

	wg.Add(2)
	go func() {
		defer wg.Done()
		do(g, "GET", "/page", lan)
		mu.Lock()
		order = append(order, "обычный")
		mu.Unlock()
	}()
	time.Sleep(20 * time.Millisecond)
	go func() {
		defer wg.Done()
		do(g, "POST", "/crit", lan)
		mu.Lock()
		order = append(order, "критичный")
		mu.Unlock()
		close(first)
	}()
	time.Sleep(20 * time.Millisecond)

	h.release <- struct{}{}
	<-h.entered
	select {
	case <-first:
	default:
	}
	close(h.release)
	wg.Wait()
	if len(order) != 2 || order[0] != "критичный" {
		t.Fatalf("порядок: %v", order)
	}
}

func TestQueueHotAndEpisodes(t *testing.T) {
	var mu sync.Mutex
	var events []bool
	g := New(http.NotFoundHandler(), testRules, smallPolicy(), nil, nil, func(started bool, _ Snapshot) {
		mu.Lock()
		events = append(events, started)
		mu.Unlock()
	})
	base := time.Unix(1000, 0)
	g.mu.Lock()
	g.recordWaitLocked(base, 200*time.Millisecond)
	g.recordWaitLocked(base.Add(100*time.Millisecond), 300*time.Millisecond)
	g.recordWaitLocked(base.Add(1100*time.Millisecond), 150*time.Millisecond)
	hot1 := g.queueHot
	g.recordWaitLocked(base.Add(1200*time.Millisecond), 0)
	g.recordWaitLocked(base.Add(2300*time.Millisecond), 0)
	hot2 := g.queueHot
	g.mu.Unlock()
	if !hot1 || hot2 {
		t.Fatalf("очередь: после медленного интервала %v, после быстрого %v", hot1, hot2)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || !events[0] || events[1] {
		t.Fatalf("эпизоды: %v", events)
	}
}

func TestRefuseTextAndHeaders(t *testing.T) {
	g := New(http.NotFoundHandler(), testRules, smallPolicy(), nil,
		[]Signal{{Name: "x", Hot: func() (bool, string) { return true, "" }}}, nil)
	rec := do(g, "GET", "/shed", lan)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "2" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("отказ: %d %v", rec.Code, rec.Header())
	}
	if body := rec.Body.String(); body == "" || !containsRussian(body) {
		t.Fatalf("текст отказа не человеческий: %q", body)
	}
}

func containsRussian(s string) bool {
	for _, r := range s {
		if r >= 'А' && r <= 'я' {
			return true
		}
	}
	return false
}
