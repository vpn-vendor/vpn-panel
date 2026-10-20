package system

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Passport() (hostcaps.Status, error) {
	var st hostcaps.Status
	resp, err := s.client().Call("host.passport", map[string]any{})
	if err != nil {
		return st, err
	}
	if resp.Error != nil {
		return st, resp.Error
	}
	err = json.Unmarshal(resp.Result, &st)
	return st, err
}

func (s *Service) Refresh() (bool, error) {
	resp, err := s.client().Call("host.refresh", map[string]any{})
	if err != nil {
		return false, err
	}
	if resp.Error != nil {
		return false, resp.Error
	}
	var r struct {
		Started bool `json:"started"`
	}
	err = json.Unmarshal(resp.Result, &r)
	return r.Started, err
}
