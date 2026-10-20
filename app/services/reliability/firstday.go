package reliability

import (
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const SettingFirstStart = "security.first_start"

func noteFirstStart(now time.Time) {
	if settings.Get(SettingFirstStart) != "" {
		return
	}
	_ = settings.Set(SettingFirstStart, strconv.FormatInt(now.Unix(), 10))
}
