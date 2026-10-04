package reliability

import (
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const SettingFirstStart = "security.first_start"

const FirstDayFor = 24 * time.Hour

func noteFirstStart(now time.Time) {
	if settings.Get(SettingFirstStart) != "" {
		return
	}
	_ = settings.Set(SettingFirstStart, strconv.FormatInt(now.Unix(), 10))
}

func FirstDay(now time.Time) bool { return firstDay(settings.Get(SettingFirstStart), now) }

func firstDay(raw string, now time.Time) bool {
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	since := now.Sub(time.Unix(sec, 0))
	return since >= 0 && since < FirstDayFor
}
