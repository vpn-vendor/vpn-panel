package multilisten

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type Listener struct {
	port   int
	logf   func(format string, args ...any)
	now    func() time.Time
	listen func(addr string) (net.Listener, error)
	conns  chan net.Conn
	done   chan struct{}
	gate   admission

	mu     sync.Mutex
	socks  map[string]net.Listener
	fails  map[string]failure
	closed bool
}

type failure struct {
	since time.Time
	inUse bool
}

func New(port int, logf func(string, ...any)) *Listener {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Listener{
		port:   port,
		logf:   logf,
		now:    time.Now,
		listen: listenFreeBind,
		conns:  make(chan net.Conn),
		done:   make(chan struct{}),
		gate:   admission{active: map[string]int{}},
		socks:  map[string]net.Listener{},
		fails:  map[string]failure{},
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
	for ip := range l.fails {
		if !want[ip] {
			delete(l.fails, ip)
		}
	}
	var errs []error

	for _, ip := range slices.Sorted(maps.Keys(want)) {
		if _, ok := l.socks[ip]; ok {
			continue
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(l.port))
		s, err := l.listen(addr)
		if err != nil {
			l.noteFailure(ip, err)
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		delete(l.fails, ip)
		l.socks[ip] = s
		l.logf("listener: bound %s", addr)
		go l.pump(s)
	}
	return errors.Join(errs...)
}

func (l *Listener) noteFailure(ip string, err error) {
	inUse := errors.Is(err, syscall.EADDRINUSE)
	if f, ok := l.fails[ip]; ok && f.inUse == inUse {
		return
	}
	l.fails[ip] = failure{since: l.now(), inUse: inUse}
}

func (l *Listener) InUse() map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for ip, f := range l.fails {
		if f.inUse {
			out[ip] = f.since
		}
	}
	return out
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
	clear(l.fails)
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
