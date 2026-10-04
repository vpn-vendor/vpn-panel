package security

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const (
	SettingHiddenMode = "security.hidden_mode"
	SettingIPv6       = "security.ipv6"
)

type Settings struct {
	HiddenMode bool
	IPv6       bool
}

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Load() Settings {
	return Settings{
		HiddenMode: s.setting(SettingHiddenMode) == "1",
		IPv6:       s.setting(SettingIPv6) == "1",
	}
}

type Status struct {
	InputFiltered bool
	PingAnswered  bool
	IPv6Closed    bool

	LeakWatch      bool
	LeakedOutbound int64

	IntentBroken bool
}

func (s *Service) Status() (*Status, error) {
	resp, err := s.client().Call("firewall.status", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		InputFiltered bool  `json:"input_filtered"`
		PingAnswered  bool  `json:"ping_answered"`
		IPv6Closed    bool  `json:"ipv6_closed"`
		LeakWatch     bool  `json:"leak_watch"`
		Leaked        int64 `json:"leaked_outbound"`
		IntentBroken  bool  `json:"intent_broken"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &Status{InputFiltered: r.InputFiltered, PingAnswered: r.PingAnswered, IPv6Closed: r.IPv6Closed,
		LeakWatch: r.LeakWatch, LeakedOutbound: r.Leaked, IntentBroken: r.IntentBroken}, nil
}

func (s *Service) setting(key string) string { return settings.Get(key) }
