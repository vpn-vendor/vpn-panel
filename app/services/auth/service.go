package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const DeviceCookie = "vp_device"

const (
	SettingMaxUsers        = "auth.max_users"
	SettingSlidingHours    = "auth.device_sliding_hours"
	SettingAbsoluteDays    = "auth.device_absolute_days"
	SettingQuarantineHours = "auth.quarantine_hours"
	SettingCodeTTLMinutes  = "auth.code_ttl_minutes"
)

var settingDefaults = map[string]int{
	SettingMaxUsers:        1,
	SettingSlidingHours:    72,
	SettingAbsoluteDays:    14,
	SettingQuarantineHours: 24,
	SettingCodeTTLMinutes:  10,
}

const (
	ViaConsole = "console"
	ViaDevice  = "device"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) SettingInt(key string) int {
	def := settingDefaults[key]
	v, err := strconv.Atoi(settings.Get(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func (s *Service) putSettingString(key, value string) error { return settings.Set(key, value) }

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

func parseInt(v string) int64 {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (s *Service) HasUsers() bool {
	count, err := facades.Orm().Query().Model(&models.User{}).Count()
	return err == nil && count > 0
}

func (s *Service) UserCount() int64 {
	count, _ := facades.Orm().Query().Model(&models.User{}).Count()
	return count
}

func (s *Service) CreateUser(name string) (*models.User, error) {
	if int(s.UserCount()) >= s.SettingInt(SettingMaxUsers) {
		return nil, fmt.Errorf("достигнут лимит учётных записей (настройка панели)")
	}
	u := models.User{Name: name, IsActive: true}
	if err := facades.Orm().Query().Create(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func viaTitle(via string) string {
	if via == ViaConsole {
		return "с консоли сервера"
	}
	return "с доверенного устройства"
}

func (s *Service) Audit(event string, userID, deviceID *uint, ip, details string) {
	securitylog.Record(models.AuthEvent{
		Event: event, UserID: userID, DeviceID: deviceID,
		IP: ip, Details: details, OccurredAt: time.Now(),
	})
}

func (s *Service) RecentEvents(limit int) []models.AuthEvent {
	var events []models.AuthEvent
	_ = facades.Orm().Query().OrderByDesc("occurred_at").Limit(limit).Find(&events)
	return events
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
