package pathmon

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

func TestNumbersFrozen(t *testing.T) {
	if ResolveEvery != 10*time.Second || RetryNoAnswer != 5*time.Minute || CandidateTries != 3 || FarShare != 0.10 ||
		FarFloor != time.Millisecond || UnderlayEvery != time.Minute || UnderlayMaxAge != 7*24*time.Hour {
		t.Fatal("числа мониторинга изменены")
	}
}

func TestSubnetFirst(t *testing.T) {
	if SubnetFirst("10.66.66.2/24, fd00::2/64") != "10.66.66.1" {
		t.Fatal("первый адрес подсети")
	}
	if SubnetFirst("10.66.66.1/24") != "" {
		t.Fatal("офис на первом адресе — дальний конец не он")
	}
	if SubnetFirst("мусор") != "" {
		t.Fatal("мусор")
	}
}

type fakeNet struct {
	mu     sync.Mutex
	rtt    map[string]time.Duration
	sent   map[string]int
	events []string
}

func (f *fakeNet) ping(ip net.IP, _ uint16, _ time.Duration) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent[ip.String()]++
	if d, ok := f.rtt[ip.String()]; ok {
		return d, nil
	}
	return 0, pathprobe.ErrTimeout
}

func newSvc(f *fakeNet, r Roles, collecting *atomic.Bool) *Service {
	return New(Deps{
		Roles: func() Roles { return r }, PeerIPv4: func() string { return "10.8.0.1" },
		AdminTarget: func(string) string { return "" }, Upstream: func() []string { return []string{"9.9.9.9", "149.112.112.112"} },
		Collecting: func() bool { return collecting.Load() }, Ping: f.ping,
		Record: func(e models.AuthEvent) {
			f.mu.Lock()
			f.events = append(f.events, e.Event+": "+e.Details)
			f.mu.Unlock()
		},
	})
}

func TestPickCandidateByPassport(t *testing.T) {
	f := &fakeNet{rtt: map[string]time.Duration{"10.8.0.1": 20 * time.Millisecond, "9.9.9.9": 25 * time.Millisecond}, sent: map[string]int{}}
	var on atomic.Bool
	on.Store(true)
	s := newSvc(f, Roles{Mode: "black", Slug: "x", Tunnel: "tun0", Candidates: []string{"admin", "pushed_gateway", "subnet_first"}, Addresses: "10.8.0.5/24"}, &on)
	addr, how := s.pickCandidate(s.d.Roles(), s.d.Upstream())
	if addr != "10.8.0.1" || how != "передана сервером" {
		t.Fatalf("%s %s", addr, how)
	}

	f2 := &fakeNet{rtt: map[string]time.Duration{"10.8.0.1": 60 * time.Millisecond, "172.16.0.1": 21 * time.Millisecond, "9.9.9.9": 25 * time.Millisecond}, sent: map[string]int{}}
	s2 := newSvc(f2, Roles{Mode: "black", Slug: "x", Tunnel: "tun0", Candidates: []string{"pushed_gateway", "subnet_first"}, Addresses: "172.16.0.9/24"}, &on)
	addr, how = s2.pickCandidate(s2.d.Roles(), s2.d.Upstream())
	if addr != "172.16.0.1" || how != "первый адрес подсети клиента" {
		t.Fatalf("далёкий кандидат не отвергнут: %s %s; события %v", addr, how, f2.events)
	}
	found := false
	for _, e := range f2.events {
		if len(e) > 20 && e[:20] == "path_target_rejected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("отказ кандидату не записан: %v", f2.events)
	}

	f3 := &fakeNet{rtt: map[string]time.Duration{}, sent: map[string]int{}}
	s3 := newSvc(f3, Roles{Mode: "black", Slug: "x", Tunnel: "tun0", Candidates: []string{"pushed_gateway"}}, &on)
	if addr, _ := s3.pickCandidate(s3.d.Roles(), s3.d.Upstream()); addr != "10.8.0.1" {
		t.Fatalf("без ответа — наблюдать первого: %s", addr)
	}
}

func TestNoPacketsWhenNotCollecting(t *testing.T) {
	f := &fakeNet{rtt: map[string]time.Duration{"9.9.9.9": 15 * time.Millisecond}, sent: map[string]int{}}
	var on atomic.Bool
	s := newSvc(f, Roles{Mode: "white", WAN: "wan0"}, &on)
	s.Resolve()
	time.Sleep(1500 * time.Millisecond)
	if s.Sent() != 0 {
		t.Fatalf("при выключенном сборе отправлено %d проб", s.Sent())
	}
	on.Store(true)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ps := s.Paths(); len(ps) == 1 && ps[0].State == pathprobe.Up {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	ps := s.Paths()
	if len(ps) != 1 || ps[0].Kind != Direct || ps[0].State != pathprobe.Up || s.Sent() == 0 {
		t.Fatalf("прямой путь: %+v, отправлено %d", ps, s.Sent())
	}
	vals, _ := s.Read()
	if vals[RowDirectRTT] != 15 {
		t.Fatalf("ряд задержки: %v", vals)
	}
	if _, ok := vals[RowDirectLoss]; ok {
		t.Fatal("потери без 1000 проб — «мало данных», ряда нет")
	}
	f.mu.Lock()
	ev := append([]string(nil), f.events...)
	f.mu.Unlock()
	if len(ev) == 0 || !strings.HasPrefix(ev[len(ev)-1], EventCode(Direct, pathprobe.Up)) {
		t.Fatalf("событие подъёма: %v", ev)
	}
	s.rebuild(Roles{}, "")
}

func TestValidateTarget(t *testing.T) {
	if v, err := ValidateTarget("10.8.0.1"); err != nil || v != "10.8.0.1" {
		t.Fatal("верный адрес")
	}
	if _, err := ValidateTarget("host.example"); err == nil {
		t.Fatal("имя вместо адреса принято")
	}
	if v, err := ValidateTarget(""); err != nil || v != "" {
		t.Fatal("пусто = снять цель")
	}
	if !errors.Is(pathprobe.ErrForbidden, pathprobe.ErrForbidden) {
		t.Fatal("ошибка запрета")
	}
}
