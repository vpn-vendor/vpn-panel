package restore

import (
	"encoding/json"
	"errors"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
)

func Live() *Importer {
	orch := network.NewOrchestrator()
	return &Importer{
		Entries: backup.Sections(),
		Agent:   agentClient{},
		System:  liveSystem{orch: orch, vpn: vpn.New()},
		Store:   settingsStore{},
		Version: updates.New().InstalledVersion,
		Now:     time.Now,
		Lock:    fileLock,
		Durable: settings.Durable,
	}
}

func fileLock() (func(), error) {
	if err := durable.MkdirAll(retention.DataDir(), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(retention.DataDir(), "import.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func Console(tell func(wait time.Duration)) *Importer {
	im := Live()
	im.Agent = patientAgent{inner: im.Agent, sleep: time.Sleep, tell: tell}
	return im
}

type patientAgent struct {
	inner Agent
	sleep func(time.Duration)
	tell  func(time.Duration)
}

func (p patientAgent) Call(method string, params, out any) error {
	err := p.inner.Call(method, params, out)
	var aerr *agentrpc.ErrorObject
	if !errors.As(err, &aerr) {
		return err
	}
	wait, ok := aerr.RetryAfter()
	if !ok {
		return err
	}
	if p.tell != nil {
		p.tell(wait)
	}
	p.sleep(wait)
	return p.inner.Call(method, params, out)
}

type agentClient struct{}

func (agentClient) Call(method string, params, out any) error {
	resp, err := (&agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}).Call(method, params)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

type liveSystem struct {
	orch *network.Orchestrator
	vpn  *vpn.Service
}

func (s liveSystem) ApplyNetwork(ip string) (bool, error) {
	st, err := s.orch.Network().Status()
	if err != nil {
		return false, err
	}
	plan := s.orch.Network().BuildPlan()
	if len(plan.Interfaces) == 0 {
		return false, ErrNoRoles
	}
	out, err := s.orch.ApplyPlan(ip, plan, st, network.ApplySecrets{})

	var aerr *agentrpc.ErrorObject
	if errors.As(err, &aerr) {
		if wait, ok := aerr.RetryAfter(); ok {
			return false, &busyError{wait: wait, cause: err}
		}
	}
	if err != nil {
		return false, err
	}
	return out.AwaitingConfirm, nil
}

func (s liveSystem) ConfirmNetwork(ip string) error {
	_, err := s.orch.Confirm(ip)
	return err
}

func (s liveSystem) CancelNetwork(ip string)         { s.orch.Cancel(ip) }
func (s liveSystem) ApplyServices(ip string) string  { return s.orch.ApplyServices(ip) }
func (s liveSystem) ConfirmTimeout() int             { return s.orch.Network().ConfirmTimeout() }
func (s liveSystem) Audit(event, ip, details string) { s.orch.Network().Audit(event, ip, details) }

func (s liveSystem) ApplyTunnel() error {
	_, err := s.vpn.Apply(s.vpn.Load())
	return err
}

func (s liveSystem) Cards() ([]CardFacts, error) {
	st, err := s.orch.Network().Status()
	if err != nil {
		return nil, err
	}
	provider := map[string]bool{}
	for _, r := range st.DefaultRoutes {
		provider[r.Dev] = true
	}
	var out []CardFacts
	for _, i := range st.Interfaces {

		if i.Loopback || network.ProductIface(i.Name) || !netplangen.ValidIfaceName(i.Name) || strings.Contains(i.Name, ".") {
			continue
		}
		out = append(out, CardFacts{Card: backup.Card{Name: i.Name, MAC: i.MAC}, Link: i.State == "UP",
			Addresses: i.Addresses, Provider: provider[i.Name], SpeedMbit: linkSpeed(i.Name)})
	}
	return out, nil
}

func linkSpeed(name string) int {
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "speed")) //nolint:gosec
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

type settingsStore struct{}

func (settingsStore) Get(k string) string   { return settings.Get(k) }
func (settingsStore) Set(k, v string) error { return settings.Set(k, v) }
