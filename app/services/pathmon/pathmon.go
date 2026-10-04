package pathmon

import (
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

type Kind string

const (
	Tunnel Kind = "tunnel"
	Beyond Kind = "beyond"
	Direct Kind = "direct"
)

const (
	ResolveEvery    = 10 * time.Second
	RetryNoAnswer   = 5 * time.Minute
	CandidateTries  = 3
	FarShare        = 0.10
	FarFloor        = time.Millisecond
	UnderlayEvery   = time.Minute
	UnderlayMaxAge  = 7 * 24 * time.Hour
	SettingUnderlay = "path.underlay"
	SettingTarget   = "vpn.probe_target."
)

type Roles struct {
	Mode       string
	Slug       string
	Protocol   string
	Addresses  string
	Tunnel     string
	WAN        string
	Candidates []string
}

type Deps struct {
	Roles       func() Roles
	PeerIPv4    func() string
	AdminTarget func(slug string) string
	Upstream    func() []string
	Collecting  func() bool
	Ping        func(ip net.IP, seq uint16, timeout time.Duration) (time.Duration, error)
	Record      func(models.AuthEvent)
	Get         func(key string) string
	Set         func(key, value string) error
	Now         func() time.Time
}

type Snapshot struct {
	Kind      Kind
	Iface     string
	Targets   []string
	Chosen    string
	State     pathprobe.State
	RTT       time.Duration
	LossPct   float64
	LossKnown bool
	Since     time.Time
	Probes    uint64
}

type path struct {
	snap Snapshot
	k    int
	hys  pathprobe.Hysteresis
	win  pathprobe.Window
	seq  uint16
	last []bool
	seen int
	stop chan struct{}
}

type Service struct {
	d            Deps
	mu           sync.Mutex
	paths        map[Kind]*path
	key          string
	lastUnderlay time.Time
	noAnswerAt   time.Time
	sent         uint64
}

func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Ping == nil {
		d.Ping = pathprobe.Ping
	}
	return &Service{d: d, paths: map[Kind]*path{}}
}

func (s *Service) Paths() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Snapshot, 0, len(s.paths))
	for _, k := range []Kind{Tunnel, Beyond, Direct} {
		if p, ok := s.paths[k]; ok {
			out = append(out, p.snap)
		}
	}
	return out
}

func (s *Service) Sent() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func (s *Service) Resolve() {
	r := s.d.Roles()
	key := r.Mode + "|" + r.Slug + "|" + r.Tunnel + "|" + r.WAN
	s.mu.Lock()
	same := key == s.key
	tunnelNoAnswer := false
	if p, ok := s.paths[Tunnel]; ok && p.snap.State == pathprobe.NoAnswer && s.d.Now().Sub(s.noAnswerAt) > RetryNoAnswer {
		tunnelNoAnswer = true
	}
	s.mu.Unlock()
	if same && !tunnelNoAnswer {
		return
	}
	s.rebuild(r, key)
}

func (s *Service) rebuild(r Roles, key string) {
	s.mu.Lock()
	for _, p := range s.paths {
		close(p.stop)
	}
	s.paths = map[Kind]*path{}
	s.key = key
	s.noAnswerAt = s.d.Now()
	s.mu.Unlock()

	ups := s.d.Upstream()
	switch {
	case r.Mode == "black" && r.Tunnel != "":
		target, how := s.pickCandidate(r, ups)
		if target != "" {
			s.start(&path{snap: Snapshot{Kind: Tunnel, Iface: r.Tunnel, Targets: []string{target}, Chosen: how}, k: 1})
		}
		if len(ups) > 0 {
			s.start(&path{snap: Snapshot{Kind: Beyond, Iface: r.Tunnel, Targets: ups}, k: 1})
		}
	case r.WAN != "" && len(ups) > 0:
		s.start(&path{snap: Snapshot{Kind: Direct, Iface: r.WAN, Targets: ups}, k: 1})
	}
}

func (s *Service) pickCandidate(r Roles, ups []string) (string, string) {
	var beyond time.Duration
	if len(ups) > 0 {
		beyond, _ = s.bestOf(ups[0])
	}
	first, firstHow := "", ""
	for _, kind := range r.Candidates {
		addr := ""
		switch kind {
		case "admin":
			addr = s.d.AdminTarget(r.Slug)
		case "pushed_gateway":
			addr = s.d.PeerIPv4()
		case "subnet_first":
			addr = SubnetFirst(r.Addresses)
		}
		if net.ParseIP(addr) == nil {
			continue
		}
		if first == "" {
			first, firstHow = addr, candidateName(kind)
		}
		rtt, ok := s.bestOf(addr)
		if !ok {
			continue
		}
		limit := beyond + time.Duration(float64(beyond)*FarShare) + FarFloor
		if beyond == 0 || rtt <= limit {
			s.record("path_target", r.Tunnel, "цель пробы внутри канала: "+addr+" ("+candidateName(kind)+"), "+rtt.Round(100*time.Microsecond).String())
			return addr, candidateName(kind)
		}
		s.record("path_target_rejected", r.Tunnel, "кандидат "+addr+" ("+candidateName(kind)+") дальше публичной цели через канал: "+rtt.Round(100*time.Microsecond).String()+" против "+beyond.Round(100*time.Microsecond).String())
	}
	if first != "" {
		s.record("path_target", r.Tunnel, "ни один кандидат не подтвердился; наблюдается "+first+" ("+firstHow+"), состояние «цель не отвечает»")
	}
	return first, firstHow
}

func candidateName(kind string) string {
	switch kind {
	case "admin":
		return "указана администратором"
	case "pushed_gateway":
		return "передана сервером"
	case "subnet_first":
		return "первый адрес подсети клиента"
	}
	return kind
}

func (s *Service) bestOf(addr string) (time.Duration, bool) {
	ip := net.ParseIP(addr)
	if ip == nil || !s.d.Collecting() {
		return 0, false
	}
	best, ok := time.Duration(0), false
	for i := 0; i < CandidateTries; i++ {
		s.mu.Lock()
		s.sent++
		s.mu.Unlock()
		rtt, err := s.d.Ping(ip, uint16(i+1), pathprobe.Timeout) //nolint:gosec
		if err == nil && (!ok || rtt < best) {
			best, ok = rtt, true
		}
	}
	return best, ok
}

func SubnetFirst(addresses string) string {
	for _, part := range splitList(addresses) {
		ip, ipnet, err := net.ParseCIDR(part)
		if err != nil || ip.To4() == nil {
			continue
		}
		first := make(net.IP, 4)
		copy(first, ipnet.IP.To4())
		first[3]++
		if first.Equal(ip.To4()) {
			continue
		}
		return first.String()
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' || c == ' ' || c == ';' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func (s *Service) start(p *path) {
	p.stop = make(chan struct{})
	p.snap.Since = s.d.Now()
	s.mu.Lock()
	s.paths[p.snap.Kind] = p
	s.mu.Unlock()
	go s.loop(p)
}

func (s *Service) loop(p *path) {
	for {
		select {
		case <-p.stop:
			return
		case <-time.After(pathprobe.NextInterval()):
		}
		if !s.d.Collecting() {
			continue
		}

		if len(p.snap.Targets) == 0 {
			continue
		}
		if p.last == nil {
			p.last = make([]bool, len(p.snap.Targets))
		}
		idx := int(p.seq) % len(p.snap.Targets)
		t := p.snap.Targets[idx]
		p.seq++
		var rtt time.Duration
		if ip := net.ParseIP(t); ip != nil {
			s.mu.Lock()
			s.sent++
			s.mu.Unlock()
			d, err := s.d.Ping(ip, p.seq, pathprobe.Timeout)
			if errors.Is(err, pathprobe.ErrForbidden) {

				log.Printf("мониторинг пути: проба %s к %s запрещена правилом выхода", p.snap.Kind, t)
				continue
			}
			p.last[idx] = err == nil
			if err == nil {
				rtt = d
			}
		}
		if p.seen < len(p.snap.Targets) {
			p.seen++
		}
		ok := pathprobe.Quorum(p.last[:p.seen], p.k)
		st, changed := p.hys.Feed(ok)
		p.win.Add(ok)
		s.mu.Lock()
		p.snap.State, p.snap.Probes = st, p.snap.Probes+1
		p.snap.RTT = rtt
		p.snap.LossPct, p.snap.LossKnown = p.win.Loss()
		if changed {
			p.snap.Since = s.d.Now()
			if st == pathprobe.NoAnswer {
				s.noAnswerAt = s.d.Now()
			}
		}
		s.mu.Unlock()
		if changed {
			s.record(EventCode(p.snap.Kind, st), p.snap.Iface, "путь «"+kindName(p.snap.Kind)+"» ("+p.snap.Iface+", цели "+joinTargets(p.snap.Targets)+"): "+st.String())
		}
		if p.snap.Kind == Direct && st == pathprobe.Up && rtt > 0 {
			s.saveUnderlay(rtt)
		}
	}
}

var (
	kinds       = []Kind{Tunnel, Beyond, Direct}
	stateSuffix = map[pathprobe.State]string{pathprobe.Up: "up", pathprobe.Down: "down", pathprobe.NoAnswer: "no_answer"}
)

func EventCode(kind Kind, st pathprobe.State) string {
	return "path_" + string(kind) + "_" + stateSuffix[st]
}

func EventCodes() []string {
	var out []string
	for _, k := range kinds {
		for _, st := range []pathprobe.State{pathprobe.Up, pathprobe.Down, pathprobe.NoAnswer} {
			out = append(out, EventCode(k, st))
		}
	}
	return out
}

func kindName(k Kind) string {
	switch k {
	case Tunnel:
		return "внутри канала"
	case Beyond:
		return "за сервером через канал"
	case Direct:
		return "прямой доступ"
	}
	return string(k)
}

func joinTargets(ts []string) string {
	out := ""
	for i, t := range ts {
		if i > 0 {
			out += ", "
		}
		out += t
	}
	return out
}

func (s *Service) record(event, iface, details string) {
	if s.d.Record != nil {
		s.d.Record(models.AuthEvent{Event: event, OccurredAt: s.d.Now(), Details: details})
	}
}

type underlay struct {
	RTTms float64 `json:"rtt_ms"`
	At    int64   `json:"at"`
}

func (s *Service) saveUnderlay(rtt time.Duration) {
	s.mu.Lock()
	due := s.d.Now().Sub(s.lastUnderlay) >= UnderlayEvery
	if due {
		s.lastUnderlay = s.d.Now()
	}
	s.mu.Unlock()
	if !due || s.d.Set == nil {
		return
	}
	b, _ := json.Marshal(underlay{RTTms: float64(rtt) / float64(time.Millisecond), At: s.d.Now().Unix()})
	_ = s.d.Set(SettingUnderlay, string(b))
}

func (s *Service) Underlay() (rttMs float64, age time.Duration, ok bool) {
	if s.d.Get == nil {
		return 0, 0, false
	}
	var u underlay
	if json.Unmarshal([]byte(s.d.Get(SettingUnderlay)), &u) != nil || u.At == 0 {
		return 0, 0, false
	}
	age = s.d.Now().Sub(time.Unix(u.At, 0))
	return u.RTTms, age, age <= UnderlayMaxAge
}

const SourceName = "path.probe"

func init() { metrics.RegisterSourceName(SourceName) }

func (s *Service) Source() metrics.Source {
	return metrics.Source{Name: SourceName, Title: "Проба пути", Rows: Rows(), Persist: true,
		Depends: "блок «Канал» на дашборде, диагнозы задержки и потерь пути", Read: s.Read}
}

const (
	RowTunnelRTT  = "path.tunnel.rtt"
	RowTunnelLoss = "path.tunnel.loss"
	RowBeyondRTT  = "path.beyond.rtt"
	RowDirectRTT  = "path.direct.rtt"
	RowDirectLoss = "path.direct.loss"
)

func Rows() []string {
	return []string{RowTunnelRTT, RowTunnelLoss, RowBeyondRTT, RowDirectRTT, RowDirectLoss}
}

func (s *Service) Read() (map[string]float64, error) {
	out := map[string]float64{}
	for _, p := range s.Paths() {
		rtt := math.NaN()
		if p.RTT > 0 && p.State == pathprobe.Up {
			rtt = float64(p.RTT) / float64(time.Millisecond)
		}
		switch p.Kind {
		case Tunnel:
			out[RowTunnelRTT] = rtt
			if p.LossKnown {
				out[RowTunnelLoss] = p.LossPct
			}
		case Beyond:
			out[RowBeyondRTT] = rtt
		case Direct:
			out[RowDirectRTT] = rtt
			if p.LossKnown {
				out[RowDirectLoss] = p.LossPct
			}
		}
	}
	for k, v := range out {
		if math.IsNaN(v) {
			delete(out, k)
		}
	}
	return out, nil
}

func ValidateTarget(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", errors.New("укажите адрес IPv4 внутри канала, например 10.8.0.1")
	}
	return ip.To4().String(), nil
}

var _ = strconv.Itoa
