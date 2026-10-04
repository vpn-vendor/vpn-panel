package overload

import (
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/priority"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/admission"
	"github.com/vpn-vendor/vpn-panel-core/internal/cgroupstat"
)

const (
	PressureHot = 50.0

	ThrottleHotShare = 0.5
)

var (
	mu   sync.Mutex
	gate *admission.Gate
)

func Wrap(next http.Handler) http.Handler {
	mu.Lock()
	defer mu.Unlock()
	pol := admission.Derive(runtime.GOMAXPROCS(0))
	gate = admission.New(next, priority.Rules, pol, trusted, Signals(), episode)
	log.Printf("vpn-panel: калитка перегрузки: %d запросов из сети (резерв %d критичным после подлинности, сбрасываемым до %d), петля %d, очередь до %d",
		pol.Ceiling, pol.Reserve, pol.ShedCeiling, pol.LoopbackCeiling, pol.QueueCeiling)
	return gate
}

func Current() *admission.Gate {
	mu.Lock()
	defer mu.Unlock()
	return gate
}

func trusted(r *http.Request) bool {
	c, err := r.Cookie(auth.DeviceCookie)
	if err != nil || c.Value == "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	_, err = auth.New().ValidateDevice(c.Value, host)
	return err == nil
}

func Signals() []admission.Signal {
	th := &throttleSignal{}
	return []admission.Signal{
		{Name: "давление процессора", Hot: pressureHot},
		{Name: "торможение квотой", Hot: th.hot},
	}
}

func pressureHot() (bool, string) {
	v, ok := cgroupstat.CPUPressure()
	if !ok {
		return false, ""
	}
	return v > PressureHot, "ожидание процессора " + strconv.FormatFloat(v, 'f', 0, 64) + " % времени"
}

type throttleSignal struct {
	last     uint64
	lastAt   time.Time
	lastHot  bool
	lastText string
}

func (t *throttleSignal) hot() (bool, string) {
	usec, ok := cgroupstat.Throttled()
	if !ok {
		return false, ""
	}
	now := time.Now()
	if t.lastAt.IsZero() {
		t.last, t.lastAt = usec, now
		return false, ""
	}
	elapsed := now.Sub(t.lastAt)
	if elapsed < 500*time.Millisecond {
		return t.lastHot, t.lastText
	}
	share := float64(usec-t.last) / 1e6 / elapsed.Seconds()
	t.last, t.lastAt = usec, now
	t.lastHot = share > ThrottleHotShare
	t.lastText = "заторможена квотой " + strconv.FormatFloat(share*100, 'f', 0, 64) + " % времени"
	return t.lastHot, t.lastText
}

func episode(started bool, s admission.Snapshot) {
	now := time.Now()
	if started {
		why := "очередь: ожидание выше цели"
		if s.SignalHot {
			why = s.SignalName + ": " + s.SignalWhy
		}
		securitylog.Record(models.AuthEvent{Event: "overload_started", OccurredAt: now, Details: why})
		return
	}
	securitylog.Record(models.AuthEvent{Event: "overload_ended", OccurredAt: now,
		Details: "длился " + now.Sub(s.Since).Round(time.Second).String() +
			", отказано: сбрасываемых " + strconv.FormatUint(s.EpisodeShed[admission.Sheddable], 10) +
			", обычных " + strconv.FormatUint(s.EpisodeShed[admission.Ordinary], 10) +
			", критичных " + strconv.FormatUint(s.EpisodeShed[admission.Critical], 10)})
}
