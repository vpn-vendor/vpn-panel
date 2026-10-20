package system

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

type LegacySettings struct {
	Found bool `json:"found"`

	Source   string             `json:"source"`
	Settings legacyvpn.Settings `json:"settings"`
}

func (s *Service) LegacySettings() (LegacySettings, error) {
	var l LegacySettings
	resp, err := s.client().Call("host.legacy_settings", map[string]any{})
	if err != nil {
		return l, err
	}
	if resp.Error != nil {
		return l, resp.Error
	}
	err = json.Unmarshal(resp.Result, &l)
	return l, err
}
