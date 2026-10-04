package agentrpc

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func startServer(t *testing.T, handlers map[string]Handler) *Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "test.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := NewServer(handlers)
	srv.logf = t.Logf
	go func() { _ = srv.Serve(l) }()
	return &Client{SocketPath: socket}
}

func pingHandlers() map[string]Handler {
	return map[string]Handler{
		"system.ping": func(json.RawMessage) (any, *ErrorObject) {
			return map[string]any{"pong": true, "agent_version": "test"}, nil
		},
	}
}

func TestPingRoundtrip(t *testing.T) {
	client := startServer(t, pingHandlers())
	resp, err := client.Call("system.ping", map[string]any{})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected method error: %v", resp.Error)
	}
	var result struct {
		Pong bool `json:"pong"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil || !result.Pong {
		t.Fatalf("bad result %s (err=%v)", resp.Result, err)
	}
}

func TestMethodNotFound(t *testing.T) {
	client := startServer(t, pingHandlers())
	resp, err := client.Call("system.unknown", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
		t.Fatalf("want -32601, got %+v", resp.Error)
	}
	if rec, ok := resp.Error.Data["recoverable"].(bool); !ok || rec {
		t.Fatalf("want recoverable=false in error.data, got %+v", resp.Error.Data)
	}
}

func TestInvalidMethodName(t *testing.T) {
	client := startServer(t, pingHandlers())
	for _, name := range []string{"ping", "a.b.c", ".ping", "ping."} {
		resp, err := client.Call(name, nil)
		if err != nil {
			t.Fatalf("call %q: %v", name, err)
		}
		if resp.Error == nil || resp.Error.Code != CodeInvalidRequest {
			t.Fatalf("method %q: want -32600, got %+v", name, resp.Error)
		}
	}
}

func TestParseErrorRepliesNullID(t *testing.T) {
	client := startServer(t, pingHandlers())
	conn, err := net.Dial("unix", client.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("{broken json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := readLine(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodeParseError || resp.ID != nil {
		t.Fatalf("want parse error with null id, got %+v", resp)
	}
}

func TestOversizedRequestDropsConnection(t *testing.T) {
	client := startServer(t, pingHandlers())
	conn, err := net.Dial("unix", client.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	huge := strings.Repeat("a", MaxMessageSize+2)
	if _, err := conn.Write([]byte(huge)); err != nil {

		return
	}
	if _, err := readLine(conn); err == nil {
		t.Fatal("want dropped connection, got a reply")
	}
}

func TestPanicInHandlerBecomesInternalError(t *testing.T) {
	client := startServer(t, map[string]Handler{
		"system.boom": func(json.RawMessage) (any, *ErrorObject) { panic("boom") },
	})
	resp, err := client.Call("system.boom", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodeInternalError {
		t.Fatalf("want -32603, got %+v", resp.Error)
	}
}

func TestTransportErrorWhenAgentDown(t *testing.T) {
	client := &Client{SocketPath: filepath.Join(t.TempDir(), "absent.sock")}
	_, err := client.Call("system.ping", nil)
	var terr *TransportError
	if !errors.As(err, &terr) {
		t.Fatalf("want *TransportError, got %v", err)
	}
	if terr.Op != "dial" {
		t.Fatalf("want dial op, got %q", terr.Op)
	}
}
