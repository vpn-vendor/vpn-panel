package httpserve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	HeaderTimeout = 10 * time.Second

	ReadTimeout = 60 * time.Second

	IdleTimeout = 60 * time.Second

	WriteGrace = 10 * time.Second

	PerAddressConns = 32

	KernelPerAddressConns = PerAddressConns / 2

	ShutdownGrace = 10 * time.Second
)

func New(handler http.Handler, requestTimeout time.Duration, maxHeaderBytes int) *http.Server {
	return newServer(handler, HeaderTimeout, ReadTimeout, requestTimeout+WriteGrace, IdleTimeout, maxHeaderBytes)
}

func newServer(handler http.Handler, header, read, write, idle time.Duration, maxHeaderBytes int) *http.Server {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: header,
		ReadTimeout:       read,
		WriteTimeout:      write,
		IdleTimeout:       idle,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	srv.ErrorLog = log.New(handshakeNoise{out: log.Writer()}, "", 0)
	return srv
}

type handshakeNoise struct{ out io.Writer }

func (h handshakeNoise) Write(p []byte) (int, error) {
	if s := string(p); strings.Contains(s, "TLS handshake error") &&
		(strings.Contains(s, "EOF") || strings.Contains(s, "connection reset by peer")) {
		return len(p), nil
	}
	return h.out.Write(p)
}

type StartFunc func() (*http.Server, func(*http.Server) error, error)

type Runner struct {
	signature string
	should    func() bool
	start     StartFunc

	mu      sync.Mutex
	srv     *http.Server
	stopped bool
}

func NewRunner(signature string, should func() bool, start StartFunc) *Runner {
	return &Runner{signature: signature, should: should, start: start}
}

func (r *Runner) Signature() string { return r.signature }

func (r *Runner) ShouldRun() bool { return r.should == nil || r.should() }

func (r *Runner) Run() error {
	srv, serve, err := r.start()
	if err != nil {
		return fmt.Errorf("%s: %w", r.signature, err)
	}
	r.mu.Lock()
	if r.stopped {

		r.mu.Unlock()
		return nil
	}
	r.srv = srv
	r.mu.Unlock()
	if err := serve(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s: %w", r.signature, err)
	}
	return nil
}

func (r *Runner) Shutdown() error {
	r.mu.Lock()
	r.stopped = true
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownGrace)
	defer cancel()
	return srv.Shutdown(ctx)
}
