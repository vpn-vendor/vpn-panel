package auth

import (
	"errors"
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

var ErrNotMain = errors.New("only the main device may sign out the others")

func DiedAt(d models.TrustedDevice, now time.Time, sliding time.Duration) time.Time {
	var died time.Time
	earlier := func(t time.Time) {
		if !t.After(now) && (died.IsZero() || t.Before(died)) {
			died = t
		}
	}
	if d.RevokedAt != nil {
		earlier(*d.RevokedAt)
	}
	earlier(d.AbsoluteExpiresAt)
	earlier(d.LastUsedAt.Add(sliding))
	return died
}

func Alive(d models.TrustedDevice, now time.Time, sliding time.Duration) bool {
	return DiedAt(d, now, sliding).IsZero()
}

func (s *Service) Sliding() time.Duration {
	return time.Duration(s.SettingInt(SettingSlidingHours)) * time.Hour
}

func (s *Service) SignOut(actor *models.TrustedDevice, ip string) error {
	now := time.Now()
	if _, err := facades.Orm().Query().Model(&models.TrustedDevice{}).Where("id", actor.ID).
		Update(map[string]any{"revoked_at": now, "revoked_by": actor.Label}); err != nil {
		return err
	}
	s.Audit("device_signed_out", &actor.UserID, &actor.ID, ip, "выход с устройства: "+actor.Label)
	return nil
}

func (s *Service) SignOutOthers(actor *models.TrustedDevice, ip string) (int, error) {
	if actor.EnrolledVia != ViaConsole || s.InQuarantine(actor) {
		return 0, ErrNotMain
	}
	now, sliding := time.Now(), s.Sliding()
	var ids []any
	for _, d := range s.Devices(actor.UserID) {
		if d.ID != actor.ID && Alive(d, now, sliding) {
			ids = append(ids, d.ID)
		}
	}
	if len(ids) > 0 {
		if _, err := facades.Orm().Query().Model(&models.TrustedDevice{}).WhereIn("id", ids).
			Update(map[string]any{"revoked_at": now, "revoked_by": actor.Label}); err != nil {
			return 0, err
		}
	}
	s.Audit("devices_signed_out", &actor.UserID, &actor.ID, ip,
		"выведено устройств: "+strconv.Itoa(len(ids))+"; осталось устройство: "+actor.Label)
	return len(ids), nil
}

func (s *Service) PurgeDead(cutoff time.Time, limit int) (int, error) {
	var ids []uint
	err := facades.Orm().Query().Model(&models.TrustedDevice{}).
		Where("(revoked_at IS NOT NULL AND revoked_at < ?) OR absolute_expires_at < ? OR last_used_at < ?",
			cutoff, cutoff, cutoff.Add(-s.Sliding())).
		OrderBy("id").Limit(limit).Pluck("id", &ids)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	del := make([]any, len(ids))
	for i, id := range ids {
		del[i] = id
	}
	if _, err := facades.Orm().Query().WhereIn("id", del).Delete(&models.TrustedDevice{}); err != nil {
		return 0, err
	}
	return len(ids), nil
}
