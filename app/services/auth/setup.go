package auth

import (
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const (
	settingSetupCodeHash    = "setup.code_hash"
	settingSetupCodeExpires = "setup.code_expires_unix"
)

func (s *Service) SetSetupCode() (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	if err := s.putSettingString(settingSetupCodeHash, hashSecret(code)); err != nil {
		return "", err
	}
	expires := time.Now().Add(15 * time.Minute).Unix()
	if err := s.putSettingString(settingSetupCodeExpires, formatInt(expires)); err != nil {
		return "", err
	}
	s.Audit("setup_code_issued", nil, nil, "console", "выдан установочный код")
	return code, nil
}

func (s *Service) CheckSetupCode(raw string) bool {
	hash := s.settingString(settingSetupCodeHash)
	expires := parseInt(s.settingString(settingSetupCodeExpires))
	if hash == "" || expires == 0 || time.Now().Unix() > expires {
		return false
	}
	return hashSecret(normalizeCode(raw)) == hash
}

func (s *Service) ClearSetupCode() {
	_ = s.putSettingString(settingSetupCodeHash, "")
	_ = s.putSettingString(settingSetupCodeExpires, "")
}

func (s *Service) settingString(key string) string { return settings.Get(key) }
