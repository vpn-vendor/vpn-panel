package multilisten

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
)

type Listener struct {
	port  int
	logf  func(format string, args ...any)
	conns chan net.Conn
	done  chan struct{}
	gate  admission

	mu     sync.Mutex
	socks  map[string]net.Listener
	closed bool
}

func New(port int, logf func(string, ...any)) *Listener {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Listener{
		port:  port,
		logf:  logf,
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
		gate:  admission{active: map[string]int{}},
		socks: map[string]net.Listener{},
	}
}

func (l *Listener) SetPerAddressLimit(n int) {
	l.gate.mu.Lock()
	l.gate.limit = n
	l.gate.mu.Unlock()
}

type admission struct {
	mu     sync.Mutex
	limit  int
	active map[string]int
}

func (a *admission) admit(ip string) (release func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.limit <= 0 || isLoopback(ip) {
		return func() {}, true
	}
	if a.active[ip] >= a.limit {
		return nil, false
	}
	a.active[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.active[ip]--; a.active[ip] <= 0 {
				delete(a.active, ip)
			}
		})
	}, true
}

func (a *admission) tracked() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

func remoteIP(c net.Conn) string {
	addr := c.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

type admittedConn struct {
	net.Conn
	release func()
}

func (c *admittedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (c *admittedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (l *Listener) Rebind(ips []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	want := map[string]bool{}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("multilisten: bad address %q", ip)
		}
		want[ip] = true
	}
	for ip, s := range l.socks {
		if !want[ip] {
			_ = s.Close()
			delete(l.socks, ip)
			l.logf("listener: unbound %s", net.JoinHostPort(ip, strconv.Itoa(l.port)))
		}
	}
	var errs []error
	for ip := range want {
		if _, ok := l.socks[ip]; ok {
			continue
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(l.port))
		s, err := listenFreeBind(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		l.socks[ip] = s
		l.logf("listener: bound %s", addr)
		go l.pump(s)
	}
	return errors.Join(errs...)
}

func (l *Listener) pump(s net.Listener) {
	for {
		c, err := s.Accept()
		if err != nil {
			return
		}
		release, ok := l.gate.admit(remoteIP(c))
		if !ok {

			_ = c.Close()
			continue
		}
		c = &admittedConn{Conn: c, release: release}
		select {
		case l.conns <- c:
		case <-l.done:
			_ = c.Close()
			return
		}
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	for ip, s := range l.socks {
		_ = s.Close()
		delete(l.socks, ip)
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ip := range sortedKeys(l.socks) {
		return l.socks[ip].Addr()
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port}
}

func (l *Listener) Bound() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return sortedKeys(l.socks)
}

func (l *Listener) Port() int { return l.port }

func sortedKeys(m map[string]net.Listener) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
