package retention

import (
	"errors"
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/oui"
)

const (
	JournalDaysDefault = 90
	JournalDaysMin     = 30
	JournalDaysMax     = 365

	ForgetDaysDefault = 30
	ForgetDaysMin     = 7
	ForgetDaysMax     = 365

	TrustKeepDaysDefault = 30
	TrustKeepDaysMin     = 7
	TrustKeepDaysMax     = 365

	OrdinaryCap      = 50000
	OrdinaryCapTight = 10000

	CriticalCap = 20000

	SystemKeepDays      = 7
	SystemKeepDaysTight = 1

	BootsKeepDays = SystemKeepDays + 1

	Batch       = 1000
	SweepBudget = time.Second
	SweepEvery  = 60 * time.Second

	CodesKeepDays = 90

	NewDevicesPerHour = 256

	DeviceWriteEvery = 60 * time.Second
)

const (
	SettingJournalDays = "retention.journal_days"
	SettingForgetDays  = "retention.devices_forget_days"
	SettingTrustDays   = "retention.trust_keep_days"
)

type Settings struct {
	JournalDays int
	ForgetDays  int
	TrustDays   int
}

func Load() Settings {
	return Settings{
		JournalDays: clamp(settingInt(SettingJournalDays), JournalDaysMin, JournalDaysMax, JournalDaysDefault),
		ForgetDays:  clamp(settingInt(SettingForgetDays), ForgetDaysMin, ForgetDaysMax, ForgetDaysDefault),
		TrustDays:   clamp(settingInt(SettingTrustDays), TrustKeepDaysMin, TrustKeepDaysMax, TrustKeepDaysDefault),
	}
}

func validateTerms(st Settings) fielderr.List {
	var errs fielderr.List
	if st.JournalDays < JournalDaysMin || st.JournalDays > JournalDaysMax {
		errs.Add("journal_days", "срок журнала безопасности — от %d до %d дней", JournalDaysMin, JournalDaysMax)
	}
	if st.ForgetDays < ForgetDaysMin || st.ForgetDays > ForgetDaysMax {
		errs.Add("devices_forget_days", "срок забывания устройств — от %d до %d дней", ForgetDaysMin, ForgetDaysMax)
	}
	if st.TrustDays < TrustKeepDaysMin || st.TrustDays > TrustKeepDaysMax {
		errs.Add("trust_keep_days", "срок хранения вышедших устройств входа — от %d до %d дней", TrustKeepDaysMin, TrustKeepDaysMax)
	}
	return errs
}

func Forgettable(d models.Device, cutoff time.Time) bool {
	return d.Label == "" && d.Location == "" && d.Owner == "" && d.Note == "" &&
		d.LabelSource == "" && d.ProposedAt == nil &&
		oui.Randomized(d.MAC) && d.LastSeenAt.Before(cutoff)
}

func clamp(v, lo, hi, def int) int {
	switch {
	case v == 0:
		return def
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

func settingInt(key string) int {
	v, err := strconv.Atoi(settings.Get(key))
	if err != nil {
		return 0
	}
	return v
}

func setSetting(key, value string) error { return settings.Set(key, value) }

var errNothing = errors.New("nothing to sweep")
