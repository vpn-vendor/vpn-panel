package policy

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

type Flag struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
	Why  string `json:"why"`
}

type Advisory struct {
	PullNow bool   `json:"pull_now"`
	Message string `json:"message"`
}

type Status struct {
	Flags    []Flag   `json:"flags"`
	Advisory Advisory `json:"advisory"`
	KnownBad []string `json:"known_bad"`
}

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Status() (*Status, error) {
	resp, err := s.client().Call("policy.status", map[string]any{})
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

func (st *Status) Active() []Flag {
	out := make([]Flag, 0, len(st.Flags))
	for _, f := range st.Flags {
		if f.On {
			out = append(out, f)
		}
	}
	return out
}
