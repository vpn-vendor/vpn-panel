package dns

import (
	"encoding/json"
	"log"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/dnsinfra"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

const SettingReady = "dns.ready"

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) BuildPlan() unboundgen.Plan {
	var rows []models.Interface
	_ = facades.Orm().Query().Where("role", "lan").Find(&rows)
	var plan unboundgen.Plan
	for _, r := range rows {
		if r.IPv4CIDR == "" {
			continue
		}
		plan.Segments = append(plan.Segments, unboundgen.Segment{Name: r.Name, CIDR: r.IPv4CIDR})
	}
	return plan
}

type Result struct {
	Changed   bool
	State     string
	Verified  bool
	Listening []string
}

func (s *Service) Apply(plan unboundgen.Plan) (*Result, error) {
	resp, err := s.client().Call("dns.apply", map[string]any{"plan": plan})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Changed   bool     `json:"changed"`
		State     string   `json:"state"`
		Verified  bool     `json:"verified"`
		Listening []string `json:"listening"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &Result{Changed: r.Changed, State: r.State, Verified: r.Verified, Listening: r.Listening}, nil
}

func (s *Service) Ready() bool { return settings.Get(SettingReady) == "1" }

func (s *Service) SetReady(ready bool) {
	value := "0"
	if ready {
		value = "1"
	}
	if err := settings.Set(SettingReady, value); err != nil {
		log.Printf("dns: %v", err)
	}
}

func (s *Service) Infra() ([]dnsinfra.Server, error) {
	resp, err := s.client().Call("dns.infra", map[string]any{"only": unboundgen.Upstream})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Servers []dnsinfra.Server `json:"servers"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.Servers, nil
}
