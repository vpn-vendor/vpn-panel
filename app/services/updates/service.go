package updates

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const SettingSeenVersion = "updates.seen_version"

type Status struct {
	Enabled     bool   `json:"enabled"`
	ToolPresent bool   `json:"tool_present"`
	TimerActive bool   `json:"timer_active"`
	Version     string `json:"version"`
	LastRun     string `json:"last_run"`
	LastResult  string `json:"last_result"`
}

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Status() (*Status, error) {
	return s.call("updates.status", map[string]any{})
}

func (s *Service) Set(enabled bool) (*Status, error) {
	return s.call("updates.set", map[string]any{"enabled": enabled})
}

func (s *Service) call(method string, params any) (*Status, error) {
	resp, err := s.client().Call(method, params)
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

const SettingNotice = "updates.notice"

var (
	checkMu   sync.Mutex
	versionOK bool
)

func (s *Service) CheckVersion() {
	checkMu.Lock()
	defer checkMu.Unlock()
	if versionOK {
		return
	}
	st, err := s.Status()
	if err != nil || st.Version == "" {

		return
	}
	versionOK = true

	seen := s.setting(SettingSeenVersion)
	_ = s.setSetting(SettingSeenVersion, st.Version)
	if seen == "" || seen == st.Version {
		return
	}
	how := "Обновление установлено вручную."
	if st.Enabled {
		how = "Обновление пришло автоматически."
	}
	_ = s.setSetting(SettingNotice, fmt.Sprintf(
		"Панель обновлена: версия %s вместо %s. %s Настройки и данные сохранены.",
		st.Version, seen, how))
	securitylog.Record(models.AuthEvent{
		Event:      "panel_upgraded",
		Details:    fmt.Sprintf("было %s, стало %s", seen, st.Version),
		OccurredAt: time.Now(),
	})
}

func (s *Service) InstalledVersion() string { return s.setting(SettingSeenVersion) }

func (s *Service) TakeNotice() string {
	msg := s.setting(SettingNotice)
	if msg != "" {
		_ = s.setSetting(SettingNotice, "")
	}
	return msg
}

func (s *Service) setting(key string) string { return settings.Get(key) }

func (s *Service) setSetting(key, value string) error { return settings.Set(key, value) }
