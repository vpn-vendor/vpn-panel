package controllers

import (
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/vpn-vendor/vpn-panel-core/app/http/assets"
	"github.com/vpn-vendor/vpn-panel-core/app/http/navigation"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
)

const devNoticeText = "Среда разработки интерфейса: сеть, файрвол и службы здесь не применяются — системные функции проверяются на установленном шлюзе. Состояние на страницах относится к контейнеру, не к серверу."

func configString(key string) string { return facades.Config().GetString(key) }

func withCsrf(ctx contractshttp.Context, data map[string]any) map[string]any {
	token, _ := ctx.Value(middleware.CtxCsrf).(string)
	data["csrf"] = token

	data["static"] = assets.Prefix()
	return data
}

func page(ctx contractshttp.Context, title, active string, data map[string]any) map[string]any {
	data = withCsrf(ctx, data)
	data["title"] = title
	data["active"] = active

	data["subtitle"] = sectionSubtitle(active)

	data["nav"] = navigation.Groups()

	data["pageWidth"] = string(navigation.WidthFor(active))

	if active != "" {
		if n := diag.New().OpenIdentifyCount(); n > 0 {
			data["navBadges"] = map[string]int64{"diagnostics": n}
		}
	}

	data["version"] = ""
	if v := updates.New().InstalledVersion(); v != "" {
		data["version"] = "v" + strings.TrimPrefix(v, "v")
	}

	if _, ok := data["searchQuery"]; !ok {
		data["searchQuery"] = ""
	}

	upd := updates.New()
	upd.CheckVersion()
	if active != "" {
		if msg := upd.TakeNotice(); msg != "" {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "info", Text: msg}}, notices...)
		}
	}
	if devmode.Enabled {
		notices, _ := data["notices"].([]notice)
		data["notices"] = append([]notice{{Level: "info", Text: devNoticeText}}, notices...)
	}

	if active != "" {
		if level, text := retention.DiskNotice(); text != "" {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: level, Text: text}}, notices...)
		}

		if text := security.LeakNotice(time.Now()); text != "" {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "error", Text: text}}, notices...)
		}

		for _, n := range securitylog.Unattended(time.Now()) {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "warn", Text: n.At.Local().Format("02.01.2006 15:04") + ": " + n.Text}}, notices...)
		}
		if st := restore.Live().Current(); st.Pending {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "error", Text: "Настройки из файла ждут подтверждения до " +
				st.Until.Local().Format("15:04:05") + ". Закрепить или откатить — на странице «Резервная копия»; без решения они вернутся к прежним сами."}}, notices...)
		}

		if fc := diag.New().FullCheck().State(); fc.Active {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "error", Text: "Идёт полная проверка сети до " +
				fc.Until.Local().Format("02.01.2006 15:04:05") + ": сняты все пределы проверки скорости, качество звонков не гарантируется. Остановить — на странице «Диагностика»."}}, notices...)
		}

		if st := diag.New().Window().State(); st.Open {
			notices, _ := data["notices"].([]notice)
			data["notices"] = append([]notice{{Level: "info", Text: "Окно проверок скорости открыто до " +
				st.Until.Local().Format("02.01.2006 15:04:05") + " (осталось " + st.Remaining(time.Now()).Round(time.Minute).String() + "). Закрыть раньше — на странице «Диагностика»."}}, notices...)
		}

		if col := metrics.Current(); col != nil {
			for _, text := range col.Notices() {
				notices, _ := data["notices"].([]notice)
				data["notices"] = append([]notice{{Level: "warn", Text: text}}, notices...)
			}
		}
	}
	return data
}

func sectionSubtitle(active string) string {
	if active == "search" {
		return "Разделы и настройки панели"
	}

	if sec, ok := navigation.SectionByKey(active); ok {
		return sec.Subtitle
	}
	return ""
}

var PathMonitor func() *pathmon.Service

var MetricsRoles func() metrics.Roles

func metricsRolesForPage() metrics.Roles {
	if MetricsRoles == nil {
		return metrics.Roles{}
	}
	return MetricsRoles()
}

func bootstrapPathMonitor() *pathmon.Service {
	if PathMonitor == nil {
		return nil
	}
	return PathMonitor()
}
