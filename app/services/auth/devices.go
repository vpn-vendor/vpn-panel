package auth

import (
	"errors"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

var ErrNotTrusted = errors.New("device is not trusted")

var ErrQuarantined = errors.New("device is quarantined")

func (s *Service) ValidateDevice(token, ip string) (*models.TrustedDevice, error) {
	if token == "" {
		return nil, ErrNotTrusted
	}
	var d models.TrustedDevice
	if err := facades.Orm().Query().Where("token_hash", hashSecret(token)).First(&d); err != nil || d.ID == 0 {
		return nil, ErrNotTrusted
	}
	now := time.Now()
	sliding := time.Duration(s.SettingInt(SettingSlidingHours)) * time.Hour
	switch {
	case d.RevokedAt != nil:
		return nil, ErrNotTrusted
	case now.After(d.AbsoluteExpiresAt):
		return nil, ErrNotTrusted
	case now.Sub(d.LastUsedAt) > sliding:
		return nil, ErrNotTrusted
	}

	if d.LastIP != ip {
		s.Audit("device_new_ip", &d.UserID, &d.ID, ip, "предыдущий адрес: "+d.LastIP)
	}

	if now.Sub(d.LastUsedAt) > time.Minute || d.LastIP != ip {
		_, _ = facades.Orm().Query().Model(&models.TrustedDevice{}).Where("id", d.ID).
			Update(map[string]any{"last_used_at": now, "last_ip": ip})
		d.LastUsedAt = now
		d.LastIP = ip
	}
	return &d, nil
}

func (s *Service) InQuarantine(d *models.TrustedDevice) bool {
	return d.QuarantineUntil != nil && time.Now().Before(*d.QuarantineUntil)
}

func (s *Service) enrollDevice(userID uint, via, label, userAgent, ip string) (string, *models.TrustedDevice, error) {
	token, err := randomToken()
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	d := models.TrustedDevice{
		UserID:            userID,
		TokenHash:         hashSecret(token),
		Label:             label,
		UserAgent:         userAgent,
		LastIP:            ip,
		EnrolledVia:       via,
		LastUsedAt:        now,
		AbsoluteExpiresAt: now.Add(time.Duration(s.SettingInt(SettingAbsoluteDays)) * 24 * time.Hour),
	}
	if via == ViaDevice {
		q := now.Add(time.Duration(s.SettingInt(SettingQuarantineHours)) * time.Hour)
		d.QuarantineUntil = &q
	}
	if err := facades.Orm().Query().Create(&d); err != nil {
		return "", nil, err
	}
	s.Audit("device_enrolled", &d.UserID, &d.ID, ip, "имя: "+label+", "+viaTitle(via))
	return token, &d, nil
}

func (s *Service) EnrollConsoleDevice(userID uint, label, userAgent, ip string) (string, *models.TrustedDevice, error) {
	return s.enrollDevice(userID, ViaConsole, label, userAgent, ip)
}

func (s *Service) Devices(userID uint) []models.TrustedDevice {
	var list []models.TrustedDevice
	_ = facades.Orm().Query().Where("user_id", userID).OrderByDesc("created_at").Find(&list)
	return list
}

func (s *Service) Revoke(actor *models.TrustedDevice, targetID uint, ip string) error {

	if targetID != actor.ID && s.InQuarantine(actor) {
		return ErrQuarantined
	}
	var target models.TrustedDevice
	if err := facades.Orm().Query().Where("id", targetID).First(&target); err != nil || target.ID == 0 {
		return errors.New("устройство не найдено")
	}
	now := time.Now()
	by := actor.Label
	_, err := facades.Orm().Query().Model(&models.TrustedDevice{}).Where("id", target.ID).
		Update(map[string]any{"revoked_at": now, "revoked_by": by})
	if err != nil {
		return err
	}
	s.Audit("device_revoked", &target.UserID, &target.ID, ip,
		"отозвано устройством: "+actor.Label)
	return nil
}

func (s *Service) RevokeAll(reason string) (int64, error) {
	now := time.Now()
	by := "console"
	affected, err := facades.Orm().Query().Model(&models.TrustedDevice{}).
		Where("revoked_at IS NULL").
		Update(map[string]any{"revoked_at": now, "revoked_by": by})
	if err != nil {
		return 0, err
	}
	s.Audit("devices_reset", nil, nil, "console", reason)
	return affected.RowsAffected, nil
}
