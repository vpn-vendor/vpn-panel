package release

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

type Status struct {
	Phase   string   `json:"phase"`
	Running string   `json:"running"`
	Anchor  string   `json:"anchor"`
	Reasons []string `json:"reasons"`
}

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Status() (*Status, error) {
	resp, err := s.client().Call("release.status", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var st Status
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Service) Accept() error {
	resp, err := s.client().Call("release.accept", map[string]any{})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

func (st *Status) Active() bool { return st.Phase != "" && st.Phase != "normal" }

func (st *Status) Settling() bool { return st.Phase == "observing" || st.Phase == "await" }
