package agentrpc

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"time"
)

type Handler func(params json.RawMessage) (any, *ErrorObject)

const IOTimeout = 10 * time.Second

type Server struct {
	handlers map[string]Handler
	logf     func(format string, args ...any)

	rootOnly map[string]bool

	peerUID func(net.Conn) (uint32, bool)
}

func NewServer(handlers map[string]Handler) *Server {
	return &Server{handlers: handlers, logf: log.Printf, rootOnly: map[string]bool{}, peerUID: peerUID}
}

func (s *Server) RootOnly(methods ...string) *Server {
	for _, m := range methods {
		s.rootOnly[m] = true
	}
	return s
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(IOTimeout))

	line, err := readLine(conn)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) {

			s.logf("agentrpc: dropped oversized request")
			return
		}
		s.logf("agentrpc: read error: %v", err)
		return
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {

		s.reply(conn, Response{Jsonrpc: Version, ID: nil, Error: &ErrorObject{
			Code: CodeParseError, Message: "parse error",
		}})
		return
	}

	if resp, ok := s.validate(req); !ok {
		s.reply(conn, resp)
		return
	}

	handler := s.handlers[req.Method]
	if handler == nil {
		s.reply(conn, Response{Jsonrpc: Version, ID: req.ID, Error: &ErrorObject{
			Code: CodeMethodNotFound, Message: "method not found",
			Data: map[string]any{"recoverable": false},
		}})
		return
	}

	if s.rootOnly[req.Method] {
		if uid, ok := s.peerUID(conn); !ok || uid != 0 {
			s.logf("agentrpc: %s refused: caller is not root", req.Method)
			s.reply(conn, Response{Jsonrpc: Version, ID: req.ID, Error: &ErrorObject{
				Code:    CodeForbidden,
				Message: "это действие выполняется только командой администратора на самом шлюзе",
				Data:    map[string]any{"recoverable": false},
			}})
			return
		}
	}

	result, methodErr := s.callSafely(handler, req)
	if methodErr != nil {
		s.reply(conn, Response{Jsonrpc: Version, ID: req.ID, Error: methodErr})
		return
	}
	payload, err := json.Marshal(result)
	if err != nil {
		s.reply(conn, Response{Jsonrpc: Version, ID: req.ID, Error: &ErrorObject{
			Code: CodeInternalError, Message: "internal error",
			Data: map[string]any{"recoverable": false},
		}})
		return
	}
	s.reply(conn, Response{Jsonrpc: Version, ID: req.ID, Result: payload})
}

func (s *Server) validate(req Request) (Response, bool) {
	invalid := func(msg string) (Response, bool) {
		return Response{Jsonrpc: Version, ID: req.ID, Error: &ErrorObject{
			Code: CodeInvalidRequest, Message: msg,
			Data: map[string]any{"recoverable": false},
		}}, false
	}
	if req.Jsonrpc != Version {
		return invalid("jsonrpc must be \"2.0\"")
	}
	if req.ID == nil {

		return invalid("id is required")
	}

	if dot := strings.Count(req.Method, "."); dot != 1 ||
		strings.HasPrefix(req.Method, ".") || strings.HasSuffix(req.Method, ".") {
		return invalid("method must be \"domain.action\"")
	}
	return Response{}, true
}

func (s *Server) callSafely(h Handler, req Request) (result any, methodErr *ErrorObject) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("agentrpc: panic in method %s: %v", req.Method, r)
			result = nil
			methodErr = &ErrorObject{
				Code: CodeInternalError, Message: "internal error",
				Data: map[string]any{"recoverable": false},
			}
		}
	}()
	return h(req.Params)
}

func (s *Server) reply(conn net.Conn, resp Response) {

	_ = conn.SetWriteDeadline(time.Now().Add(IOTimeout))
	if err := writeMessage(conn, resp); err != nil {
		s.logf("agentrpc: write error: %v", err)
	}
}
