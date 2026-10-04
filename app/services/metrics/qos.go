package metrics

import (
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
)

const (
	RowWANVoiceDelay    = "qos.wan.voice.delay"
	RowWANVoiceDrops    = "qos.wan.voice.drops"
	RowTunnelVoiceDelay = "qos.tunnel.voice.delay"
	RowTunnelVoiceDrops = "qos.tunnel.voice.drops"
)

func voiceTin(n int) (int, bool) {
	switch n {
	case 3:
		return 2, true
	case 4:
		return 3, true
	}
	return 0, false
}

type qosPrev struct {
	ifIndex int
	drops   uint32
	at      time.Time
}

type QoSSource struct {
	roles func() Roles
	dump  func() ([]rtnl.Qdisc, error)
	links func() ([]rtnl.Link, error)
	now   func() time.Time
	mu    sync.Mutex
	prev  map[string]qosPrev
	norm  map[string]VoiceNorm
}

type VoiceNorm struct {
	TargetMs   float64
	IntervalMs float64
}

var (
	voiceMu  sync.Mutex
	voiceOne *QoSSource
)

func VoiceNormFor(row string) (VoiceNorm, bool) {
	voiceMu.Lock()
	q := voiceOne
	voiceMu.Unlock()
	if q == nil {
		return VoiceNorm{}, false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	n, ok := q.norm[row]
	return n, ok
}

func NewQoSSource(roles func() Roles, dump func() ([]rtnl.Qdisc, error), links func() ([]rtnl.Link, error)) *QoSSource {
	q := &QoSSource{roles: roles, dump: dump, links: links, now: time.Now, prev: map[string]qosPrev{}, norm: map[string]VoiceNorm{}}
	voiceMu.Lock()
	voiceOne = q
	voiceMu.Unlock()
	return q
}

func (q *QoSSource) Source() Source {
	return Source{Name: "qos.voice", Title: "Очередь звонков", Rows: []string{RowWANVoiceDelay, RowWANVoiceDrops, RowTunnelVoiceDelay, RowTunnelVoiceDrops},
		Persist: true, Depends: "график «Звонки»", Read: q.read}
}

func (q *QoSSource) read() (map[string]float64, error) {
	r := q.roles()
	links, err := q.links()
	if err != nil {
		return nil, err
	}
	qdiscs, err := q.dump()
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	for _, l := range links {
		index[l.Name] = l.Index
	}
	byIndex := map[int]rtnl.Qdisc{}
	for _, qd := range qdiscs {
		if qd.Kind == "cake" && len(qd.Tins) > 0 {
			byIndex[qd.IfIndex] = qd
		}
	}
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()
	out := map[string]float64{}
	take := func(name, rowDelay, rowDrops string) {

		delete(q.norm, rowDelay)
		idx, ok := index[name]
		if !ok || name == "" {
			delete(q.prev, name)
			return
		}
		qd, ok := byIndex[idx]
		if !ok {
			delete(q.prev, name)
			return
		}
		tin, ok := voiceTin(len(qd.Tins))
		if !ok {
			return
		}
		t := qd.Tins[tin]
		out[rowDelay] = float64(t.AvgDelayUs) / 1000
		if t.TargetUs > 0 && t.IntervalUs > t.TargetUs {
			q.norm[rowDelay] = VoiceNorm{TargetMs: float64(t.TargetUs) / 1000, IntervalMs: float64(t.IntervalUs) / 1000}
		}
		p, had := q.prev[name]
		q.prev[name] = qosPrev{ifIndex: idx, drops: t.DroppedPackets, at: now}

		if !had || p.ifIndex != idx || t.DroppedPackets < p.drops {
			return
		}
		if dt := now.Sub(p.at).Seconds(); dt > 0 {
			out[rowDrops] = float64(t.DroppedPackets-p.drops) / dt
		}
	}
	take(r.WAN, RowWANVoiceDelay, RowWANVoiceDrops)
	take(r.Tunnel, RowTunnelVoiceDelay, RowTunnelVoiceDrops)
	return out, nil
}
