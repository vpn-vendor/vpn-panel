package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
)

type Roles struct {
	WAN    string
	LANs   []string
	Tunnel string
}

const (
	RowWANRx    = "net.wan.rx"
	RowWANTx    = "net.wan.tx"
	RowLANRx    = "net.lan.rx"
	RowLANTx    = "net.lan.tx"
	RowTunnelRx = "net.tunnel.rx"
	RowTunnelTx = "net.tunnel.tx"
)

type linkPrev struct {
	index  int
	rx, tx uint64
	at     time.Time
}

type LinkSource struct {
	roles func() Roles
	dump  func() ([]rtnl.Link, error)
	now   func() time.Time
	dirty atomic.Bool
	mu    sync.Mutex
	cur   Roles
	prev  map[string]linkPrev
}

func NewLinkSource(roles func() Roles, dump func() ([]rtnl.Link, error)) *LinkSource {
	l := &LinkSource{roles: roles, dump: dump, now: time.Now, prev: map[string]linkPrev{}}
	l.dirty.Store(true)
	return l
}

func (l *LinkSource) Invalidate() { l.dirty.Store(true) }

func (l *LinkSource) Source() Source {
	return Source{Name: "net.links", Title: "Трафик карт",
		Rows:    []string{RowWANRx, RowWANTx, RowLANRx, RowLANTx, RowTunnelRx, RowTunnelTx},
		Persist: true, Depends: "график «Трафик»", Read: l.read}
}

func (l *LinkSource) read() (map[string]float64, error) {
	if l.dirty.Swap(false) {
		r := l.roles()
		l.mu.Lock()
		l.cur = r
		l.mu.Unlock()
	}
	links, err := l.dump()
	if err != nil {
		l.dirty.Store(true)
		return nil, err
	}
	now := l.now()
	byName := make(map[string]rtnl.Link, len(links))
	for _, lk := range links {
		byName[lk.Name] = lk
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]float64{}
	rate := func(name string) (rx, tx float64, ok bool) {
		lk, found := byName[name]
		if !found || !lk.HasStats {
			return 0, 0, false
		}
		p, had := l.prev[name]
		l.prev[name] = linkPrev{index: lk.Index, rx: lk.RxBytes, tx: lk.TxBytes, at: now}
		if !had || p.index != lk.Index || lk.RxBytes < p.rx || lk.TxBytes < p.tx {
			return 0, 0, false
		}
		dt := now.Sub(p.at).Seconds()
		if dt <= 0 {
			return 0, 0, false
		}
		return float64(lk.RxBytes-p.rx) / dt, float64(lk.TxBytes-p.tx) / dt, true
	}

	for name := range l.prev {
		if _, found := byName[name]; !found {
			delete(l.prev, name)
		}
	}
	if rx, tx, ok := rate(l.cur.WAN); ok {
		out[RowWANRx], out[RowWANTx] = rx, tx
	}
	if rx, tx, ok := rate(l.cur.Tunnel); ok {
		out[RowTunnelRx], out[RowTunnelTx] = rx, tx
	}

	var lrx, ltx float64
	known := len(l.cur.LANs) > 0
	for _, name := range l.cur.LANs {

		rx, tx, ok := rate(name)
		if !ok {
			known = false
			continue
		}
		lrx, ltx = lrx+rx, ltx+tx
	}
	if known {
		out[RowLANRx], out[RowLANTx] = lrx, ltx
	}
	return out, nil
}
