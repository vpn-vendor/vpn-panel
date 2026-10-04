package agentrpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const (
	ConnectTimeout = 2 * time.Second
	WriteTimeout   = 10 * time.Second
	ReadTimeout    = 10 * time.Second
)

type Client struct {
	SocketPath string
}

func (c *Client) Call(method string, params any) (*Response, error) {
	return c.CallWithin(method, params, ReadTimeout)
}

func (c *Client) CallWithin(method string, params any, respTimeout time.Duration) (*Response, error) {
	req := Request{Jsonrpc: Version, ID: newID(), Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, &TransportError{Op: "encode", Err: err}
		}
		req.Params = raw
	}

	conn, err := net.DialTimeout("unix", c.SocketPath, ConnectTimeout)
	if err != nil {
		return nil, &TransportError{Op: "dial", Err: err}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if err := writeMessage(conn, req); err != nil {
		return nil, &TransportError{Op: "write", Err: err}
	}

	_ = conn.SetReadDeadline(time.Now().Add(respTimeout))
	line, err := readLine(conn)
	if err != nil {
		return nil, &TransportError{Op: "read", Err: err}
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, &TransportError{Op: "decode", Err: err}
	}

	if resp.Jsonrpc != Version {
		return nil, &TransportError{Op: "decode", Err: fmt.Errorf("unexpected jsonrpc version %q", resp.Jsonrpc)}
	}
	if resp.Error == nil && !idEqual(resp.ID, req.ID) {
		return nil, &TransportError{Op: "decode", Err: fmt.Errorf("response id mismatch")}
	}
	return &resp, nil
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func idEqual(a, b any) bool {
	if a == b {
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
