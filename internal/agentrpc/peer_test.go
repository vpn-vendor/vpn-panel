package agentrpc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func rootOnlyServer(t *testing.T, uid func(net.Conn) (uint32, bool)) *Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "peer.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := NewServer(map[string]Handler{
		"backup.code": func(json.RawMessage) (any, *ErrorObject) { return map[string]any{"code": "секрет"}, nil },
		"system.ping": func(json.RawMessage) (any, *ErrorObject) { return map[string]any{"pong": true}, nil },
	}).RootOnly("backup.code")
	srv.logf = t.Logf
	if uid != nil {
		srv.peerUID = uid
	}
	go func() { _ = srv.Serve(l) }()
	return &Client{SocketPath: socket}
}

func callCode(t *testing.T, c *Client, method string) *ErrorObject {
	t.Helper()
	resp, err := c.Call(method, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Error
}

func TestRootOnlyRefusesOthers(t *testing.T) {
	for name, uid := range map[string]func(net.Conn) (uint32, bool){
		"панель":     func(net.Conn) (uint32, bool) { return 999, true },
		"неизвестен": func(net.Conn) (uint32, bool) { return 0, false },
	} {
		c := rootOnlyServer(t, uid)
		if e := callCode(t, c, "backup.code"); e == nil || e.Code != CodeForbidden {
			t.Errorf("%s: метод только для root ответил: %+v", name, e)
		}
		if e := callCode(t, c, "system.ping"); e != nil {
			t.Errorf("%s: обычный метод закрыт: %+v", name, e)
		}
	}
	c := rootOnlyServer(t, func(net.Conn) (uint32, bool) { return 0, true })
	if e := callCode(t, c, "backup.code"); e != nil {
		t.Fatalf("root получил отказ: %+v", e)
	}
}

func TestPeerUIDFromKernel(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "uid.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	got := make(chan uint32, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		uid, ok := peerUID(conn)
		if !ok {
			uid = ^uint32(0)
		}
		got <- uid
	}()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if uid := <-got; uid != uint32(os.Geteuid()) { //nolint:gosec
		t.Fatalf("ядро сообщило uid %d, процесс — %d", uid, os.Geteuid())
	}

	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, ok := peerUID(a); ok {
		t.Fatal("у канала без сокета найден вызывающий")
	}
}
