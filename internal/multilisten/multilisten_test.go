package multilisten

import (
	"errors"
	"net"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func dialOK(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func TestRebindAddRemoveAndAccept(t *testing.T) {
	port := freePort(t)
	l := New(port, nil)
	defer func() { _ = l.Close() }()

	if err := l.Rebind([]string{"127.0.0.1"}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if got := l.Bound(); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("bound = %v", got)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	if !dialOK(t, addr) {
		t.Fatal("dial 127.0.0.1 failed")
	}
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Accept не получил соединение")
	}

	if err := l.Rebind([]string{"127.0.0.1"}); err != nil {
		t.Fatalf("rebind idempotent: %v", err)
	}

	if err := l.Rebind(nil); err != nil {
		t.Fatalf("rebind empty: %v", err)
	}
	if len(l.Bound()) != 0 || dialOK(t, addr) {
		t.Fatal("после Rebind(nil) сокет должен быть закрыт")
	}
}

func TestRebindRejectsGarbage(t *testing.T) {
	l := New(freePort(t), nil)
	defer func() { _ = l.Close() }()
	if err := l.Rebind([]string{"not-an-ip"}); err == nil {
		t.Fatal("мусор вместо адреса обязан отвергаться")
	}
}

func TestFreeBindToAbsentAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("IP_FREEBIND есть только в Linux")
	}
	l := New(freePort(t), nil)
	defer func() { _ = l.Close() }()

	if err := l.Rebind([]string{"192.0.2.10"}); err != nil {
		t.Fatalf("freebind: %v", err)
	}
}

func TestInUseWhileAnotherSocketHoldsPort(t *testing.T) {
	occupant, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := occupant.Addr().(*net.TCPAddr).Port
	l := New(port, nil)
	defer func() { _ = l.Close() }()

	err = l.Rebind([]string{"127.0.0.1"})
	if !errors.Is(err, syscall.EADDRINUSE) {
		_ = occupant.Close()
		t.Fatalf("ждали «адрес занят», получили %v", err)
	}
	if _, ok := l.InUse()["127.0.0.1"]; !ok || len(l.Bound()) != 0 {
		_ = occupant.Close()
		t.Fatalf("занятый адрес: InUse = %v, Bound = %v", l.InUse(), l.Bound())
	}

	if err := occupant.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Rebind([]string{"127.0.0.1"}); err != nil {
		t.Fatalf("после ухода чужого: %v", err)
	}
	if got := l.Bound(); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("bound = %v", got)
	}
	if got := l.InUse(); len(got) != 0 {
		t.Fatalf("InUse после привязки = %v", got)
	}
}

type stubSock struct {
	once sync.Once
	done chan struct{}
}

func newStubSock() *stubSock { return &stubSock{done: make(chan struct{})} }

func (s *stubSock) Accept() (net.Conn, error) {
	<-s.done
	return nil, net.ErrClosed
}

func (s *stubSock) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *stubSock) Addr() net.Addr { return &net.TCPAddr{} }

func bindErr(errno syscall.Errno) error {
	return &net.OpError{Op: "listen", Net: "tcp4", Err: os.NewSyscallError("bind", errno)}
}

func TestInUseStreaks(t *testing.T) {
	const a, b = "10.0.0.1", "10.0.0.2"
	inUse, notAvail := bindErr(syscall.EADDRINUSE), bindErr(syscall.EADDRNOTAVAIL)
	steps := []struct {
		name   string
		at     time.Duration
		want   []string
		result map[string]error
		inUse  map[string]time.Duration
		bound  []string
	}{
		{"занят и недоступен", 0, []string{a, b},
			map[string]error{a: inUse, b: notAvail}, map[string]time.Duration{a: 0}, nil},
		{"полоса продолжается", 5 * time.Second, []string{a, b},
			map[string]error{a: inUse, b: notAvail}, map[string]time.Duration{a: 0}, nil},
		{"сменился род ошибки", 10 * time.Second, []string{a, b},
			map[string]error{a: notAvail, b: notAvail}, map[string]time.Duration{}, nil},
		{"снова занят — новая полоса", 15 * time.Second, []string{a, b},
			map[string]error{a: inUse, b: notAvail}, map[string]time.Duration{a: 15 * time.Second}, nil},
		{"адрес больше не нужен", 20 * time.Second, []string{b},
			map[string]error{b: notAvail}, map[string]time.Duration{}, nil},
		{"вернулся занятым", 25 * time.Second, []string{a, b},
			map[string]error{a: inUse, b: inUse}, map[string]time.Duration{a: 25 * time.Second, b: 25 * time.Second}, nil},
		{"один освободился", 30 * time.Second, []string{a, b},
			map[string]error{b: inUse}, map[string]time.Duration{b: 25 * time.Second}, []string{a}},
		{"всё привязано", 35 * time.Second, []string{a, b},
			nil, map[string]time.Duration{}, []string{a, b}},
	}

	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	var clock time.Time
	var result map[string]error
	l := New(80, nil)
	l.now = func() time.Time { return clock }
	l.listen = func(addr string) (net.Listener, error) {
		host, _, _ := net.SplitHostPort(addr)
		if err := result[host]; err != nil {
			return nil, err
		}
		return newStubSock(), nil
	}

	for _, st := range steps {
		clock, result = start.Add(st.at), st.result
		err := l.Rebind(st.want)
		if (err != nil) != (len(st.result) > 0) {
			t.Fatalf("%s: ошибка привязки = %v", st.name, err)
		}
		if err != nil {
			if lines := strings.Split(err.Error(), "\n"); !slices.IsSorted(lines) {
				t.Fatalf("%s: порядок ошибок плавает: %q", st.name, lines)
			}
		}
		want := map[string]time.Time{}
		for ip, d := range st.inUse {
			want[ip] = start.Add(d)
		}
		if got := l.InUse(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: InUse = %v, ждали %v", st.name, got, want)
		}
		if got := l.Bound(); !slices.Equal(got, st.bound) {
			t.Fatalf("%s: Bound = %v, ждали %v", st.name, got, st.bound)
		}
	}

	result = map[string]error{"10.0.0.3": inUse}
	if err := l.Rebind([]string{a, b, "10.0.0.3"}); err == nil || len(l.InUse()) != 1 {
		t.Fatalf("третий адрес занят: err = %v, InUse = %v", err, l.InUse())
	}
	_ = l.Close()
	if got := l.InUse(); len(got) != 0 {
		t.Fatalf("после Close InUse = %v", got)
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	l := New(freePort(t), nil)
	_ = l.Rebind([]string{"127.0.0.1"})
	errCh := make(chan error, 1)
	go func() { _, err := l.Accept(); errCh <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = l.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("want net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept не проснулся после Close")
	}
	if err := l.Rebind([]string{"127.0.0.1"}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Rebind после Close: %v", err)
	}
}

func TestAddrFallback(t *testing.T) {
	l := New(4443, nil)
	defer func() { _ = l.Close() }()
	if got := l.Addr().String(); got != "127.0.0.1:4443" {
		t.Fatalf("Addr без сокетов = %s", got)
	}
}

func TestAdmissionPerAddress(t *testing.T) {
	a := admission{active: map[string]int{}, limit: 2}
	r1, ok1 := a.admit("192.0.2.1")
	_, ok2 := a.admit("192.0.2.1")
	if _, ok3 := a.admit("192.0.2.1"); !ok1 || !ok2 || ok3 {
		t.Fatalf("предел 2: %v %v %v", ok1, ok2, ok3)
	}
	if _, ok := a.admit("192.0.2.2"); !ok {
		t.Fatal("другой адрес не зависит от первого")
	}
	r1()
	r1()
	if _, ok := a.admit("192.0.2.1"); !ok {
		t.Fatal("освобождение не вернуло место")
	}
	if _, ok := a.admit("192.0.2.1"); ok {
		t.Fatal("повторное освобождение открыло лишнее место")
	}
	for i := 0; i < 100; i++ {
		if _, ok := a.admit("127.0.0.1"); !ok {
			t.Fatal("петля не ограничивается")
		}
	}
	b := admission{active: map[string]int{}, limit: 1}
	rel, _ := b.admit("192.0.2.9")
	rel()
	if b.tracked() != 0 {
		t.Fatal("запись адреса без соединений не удалена")
	}
}

func TestAcceptedConnReleasesOnClose(t *testing.T) {
	port := freePort(t)
	l := New(port, nil)
	l.SetPerAddressLimit(1)
	defer func() { _ = l.Close() }()
	if err := l.Rebind([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case c := <-accepted:
		if _, ok := c.(*admittedConn); !ok {
			t.Fatalf("соединение не под учётом: %T", c)
		}
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Accept не получил соединение")
	}
	if l.gate.tracked() != 0 {
		t.Fatal("петля не должна попадать в учёт")
	}
}

func itoa(i int) string { return net.JoinHostPort("", "")[:0] + intToStr(i) }

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
