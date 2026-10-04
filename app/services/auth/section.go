package auth

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

const (
	MaxUsersMin     = 1
	MaxUsersMax     = 50
	AbsoluteDaysMin = 1
	AbsoluteDaysMax = 30
	CodeTTLMin      = 3
	CodeTTLMax      = 10
	SlidingHoursMin = 1
	QuarantineMin   = 1
)

type Section struct {
	MaxUsers           int `json:"max_users" setting:"auth.max_users"`
	DeviceSlidingHours int `json:"device_sliding_hours" setting:"auth.device_sliding_hours"`
	DeviceAbsoluteDays int `json:"device_absolute_days" setting:"auth.device_absolute_days"`
	QuarantineHours    int `json:"quarantine_hours" setting:"auth.quarantine_hours"`
	CodeTTLMinutes     int `json:"code_ttl_minutes" setting:"auth.code_ttl_minutes"`
}

func ReadSection() (Section, error) {
	svc := New()
	return Section{
		MaxUsers:           svc.SettingInt(SettingMaxUsers),
		DeviceSlidingHours: svc.SettingInt(SettingSlidingHours),
		DeviceAbsoluteDays: svc.SettingInt(SettingAbsoluteDays),
		QuarantineHours:    svc.SettingInt(SettingQuarantineHours),
		CodeTTLMinutes:     svc.SettingInt(SettingCodeTTLMinutes),
	}, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	if v.MaxUsers < MaxUsersMin || v.MaxUsers > MaxUsersMax {
		errs.Add("max_users", "учётных записей — от %d до %d", MaxUsersMin, MaxUsersMax)
	}
	absOK := v.DeviceAbsoluteDays >= AbsoluteDaysMin && v.DeviceAbsoluteDays <= AbsoluteDaysMax
	if !absOK {
		errs.Add("device_absolute_days", "срок доверия устройства — от %d до %d дней", AbsoluteDaysMin, AbsoluteDaysMax)
	}
	absHours := v.DeviceAbsoluteDays * 24
	if v.DeviceSlidingHours < SlidingHoursMin || (absOK && v.DeviceSlidingHours > absHours) {
		errs.Add("device_sliding_hours", "срок неактивности — от %d часа до срока доверия устройства", SlidingHoursMin)
	}
	if v.QuarantineHours < QuarantineMin || (absOK && v.QuarantineHours >= absHours) {
		errs.Add("quarantine_hours", "карантин нового устройства — от %d часа и короче срока доверия", QuarantineMin)
	}
	if v.CodeTTLMinutes < CodeTTLMin || v.CodeTTLMinutes > CodeTTLMax {
		errs.Add("code_ttl_minutes", "срок кода подключения — от %d до %d минут", CodeTTLMin, CodeTTLMax)
	}
	return errs
}

func ApplySection(cur, want Section) error { return settings.WriteChanged(cur, want) }

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}
