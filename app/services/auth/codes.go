package auth

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTWXYZ"

var ErrBadCode = errors.New("код не подходит или истёк")

func generateCode() (string, error) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(codeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

func normalizeCode(raw string) string {
	up := strings.ToUpper(strings.TrimSpace(raw))
	up = strings.ReplaceAll(up, " ", "")
	up = strings.ReplaceAll(up, "-", "")
	if len(up) == 8 {
		up = up[:4] + "-" + up[4:]
	}
	return up
}

func (s *Service) IssueCode(userID uint, via string, byDevice *models.TrustedDevice, ip string) (string, error) {
	if via == ViaDevice {
		if byDevice == nil {
			return "", errors.New("device required")
		}
		if s.InQuarantine(byDevice) {
			return "", ErrQuarantined
		}
	}
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	row := models.EnrollCode{
		CodeHash:  hashSecret(code),
		UserID:    userID,
		IssuedVia: via,
		ExpiresAt: time.Now().Add(time.Duration(s.SettingInt(SettingCodeTTLMinutes)) * time.Minute),
	}
	var deviceID *uint
	if byDevice != nil {
		deviceID = &byDevice.ID
		row.IssuedByDeviceID = &byDevice.ID
	}
	if err := facades.Orm().Query().Create(&row); err != nil {
		return "", err
	}
	s.Audit("code_issued", &userID, deviceID, ip, viaTitle(via))
	return code, nil
}

func (s *Service) UseCode(rawCode, label, userAgent, ip string) (string, *models.TrustedDevice, error) {
	var row models.EnrollCode
	err := facades.Orm().Query().Where("code_hash", hashSecret(normalizeCode(rawCode))).First(&row)
	if err != nil || row.ID == 0 || row.UsedAt != nil || time.Now().After(row.ExpiresAt) {
		s.Audit("code_failed", nil, nil, ip, "неудачный ввод кода")
		return "", nil, ErrBadCode
	}
	now := time.Now()
	if _, err := facades.Orm().Query().Model(&models.EnrollCode{}).Where("id", row.ID).
		Update(map[string]any{"used_at": now, "used_by_ip": ip}); err != nil {
		return "", nil, err
	}
	if label = strings.TrimSpace(label); label == "" {
		label = "Без имени"
	}
	return s.enrollDevice(row.UserID, row.IssuedVia, label, userAgent, ip)
}
