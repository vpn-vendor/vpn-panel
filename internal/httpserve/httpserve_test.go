package httpserve

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApprovedTimeouts(t *testing.T) {
	srv := New(http.NotFoundHandler(), 120*time.Second, 1<<20)
	checks := []struct {
		name      string
		got, want time.Duration
	}{
		{"рукопожатие и заголовки", srv.ReadHeaderTimeout, 10 * time.Second},
		{"чтение запроса", srv.ReadTimeout, 60 * time.Second},
		{"запись ответа", srv.WriteTimeout, 130 * time.Second},
		{"простой", srv.IdleTimeout, 60 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: %v, утверждено %v", c.name, c.got, c.want)
		}
	}
	if PerAddressConns != 32 {
		t.Errorf("соединений с адреса: %d, утверждено 32", PerAddressConns)
	}

	if KernelPerAddressConns != 16 {
		t.Errorf("предел ядра на адрес: %d, утверждено 16 — половина предела слушателя", KernelPerAddressConns)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("предел заголовков не передан: %d", srv.MaxHeaderBytes)
	}
}

func waitClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	_, err := io.ReadAll(c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("сервер не закрыл молчащее соединение за %v", within)
	}
}

func TestSlowHeadersAreCut(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.Config = newServer(ts.Config.Handler, 200*time.Millisecond, time.Second, time.Second, time.Second, 1<<20)
	ts.Start()
	defer ts.Close()

	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, c, 3*time.Second)
}

func TestSilentTLSHandshakeIsCut(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.Config = newServer(ts.Config.Handler, 200*time.Millisecond, time.Second, time.Second, time.Second, 1<<20)
	ts.StartTLS()
	defer ts.Close()

	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitClosed(t, c, 3*time.Second)
}

func startOnLoopback(t *testing.T) (StartFunc, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	start := func() (*http.Server, func(*http.Server) error, error) {
		srv := New(http.NotFoundHandler(), time.Second, 1<<20)
		return srv, func(s *http.Server) error { return s.Serve(l) }, nil
	}
	return start, l.Addr().String()
}

func TestRunnerServesAndShutsDown(t *testing.T) {
	start, addr := startOnLoopback(t)
	r := NewRunner("test:http", nil, start)
	if !r.ShouldRun() || r.Signature() != "test:http" {
		t.Fatal("контракт исполнителя нарушен")
	}
	done := make(chan error, 1)
	go func() { done <- r.Run() }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("сервер не поднялся: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := r.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("штатная остановка не должна быть ошибкой: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run не вернулся после Shutdown")
	}
}

func TestShutdownBeforeRun(t *testing.T) {
	start, _ := startOnLoopback(t)
	r := NewRunner("test:early", nil, start)
	if err := r.Shutdown(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ранняя остановка: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run обслуживает после Shutdown")
	}
}

func TestRunnerReportsStartError(t *testing.T) {
	r := NewRunner("test:broken", func() bool { return false }, func() (*http.Server, func(*http.Server) error, error) {
		return nil, nil, errors.New("слушатель не подготовлен")
	})
	if r.ShouldRun() {
		t.Fatal("should=false обязан выключать исполнитель")
	}
	if err := r.Run(); err == nil {
		t.Fatal("ошибка подготовки обязана вернуться")
	}
}
