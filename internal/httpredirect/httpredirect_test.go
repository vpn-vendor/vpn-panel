package httpredirect

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startOnFreePort(t *testing.T, externalTLSPort string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	srv := &http.Server{Handler: Handler(externalTLSPort), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	time.Sleep(50 * time.Millisecond)
	return addr
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRedirectKeepsPathAndSetsPort(t *testing.T) {
	addr := startOnFreePort(t, "8443")
	resp := get(t, fmt.Sprintf("http://%s/network?x=1", addr))
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("want 301, got %d", resp.StatusCode)
	}
	want := "https://127.0.0.1:8443/network?x=1"
	if loc := resp.Header.Get("Location"); loc != want {
		t.Fatalf("location: want %q, got %q", want, loc)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 128 {
		t.Fatalf("redirect body suspiciously large: %d bytes", len(body))
	}
}

func TestPort443IsOmitted(t *testing.T) {
	addr := startOnFreePort(t, "443")
	resp := get(t, fmt.Sprintf("http://%s/", addr))
	if loc := resp.Header.Get("Location"); loc != "https://127.0.0.1/" {
		t.Fatalf("location: got %q", loc)
	}
}

func TestNoContentServedOverHTTP(t *testing.T) {
	addr := startOnFreePort(t, "8443")
	for _, path := range []string{"/public/panel.css", "/health", "/agent/ping"} {
		resp := get(t, fmt.Sprintf("http://%s%s", addr, path))
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("%s: want 301, got %d", path, resp.StatusCode)
		}
	}
}
