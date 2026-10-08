package routes

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/http/assets"
	"github.com/vpn-vendor/vpn-panel-core/app/http/controllers"
	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
)

func Web() {

	facades.Route().GlobalMiddleware(
		middleware.NewSecurityHeaders(),
		middleware.NewCsrfGuard(),
		middleware.NewAuthenticate(),
	)

	home := controllers.NewHomeController()
	facades.Route().Get("/", home.Index)
	facades.Route().Get("/health", home.Health)

	search := controllers.NewSearchController()
	facades.Route().Get("/search", search.Index)

	setup := controllers.NewSetupController()
	facades.Route().Get("/setup", setup.Show)
	facades.Route().Post("/setup", setup.Store)
	facades.Route().Post("/setup/answer", setup.Answer)
	facades.Route().Post("/setup/speed", setup.SpeedStore)
	facades.Route().Get("/setup/{step}", setup.Step)
	login := controllers.NewLoginController()
	facades.Route().Get("/login", login.Show)
	facades.Route().Post("/login", login.Enter)

	dnsController := controllers.NewDnsController()
	facades.Route().Get("/dns", dnsController.Index)

	facades.Route().Get("/help", controllers.NewHelpController().Index)

	qosController := controllers.NewQosController()
	facades.Route().Get("/qos", qosController.Index)
	facades.Route().Post("/qos/apply", qosController.Apply)
	facades.Route().Post("/qos/speedtest", qosController.Speedtest)
	facades.Route().Get("/qos/speedtest/status", qosController.SpeedtestStatus)

	dhcpController := controllers.NewDhcpController()
	facades.Route().Get("/dhcp", dhcpController.Index)
	facades.Route().Post("/dhcp/reserve", dhcpController.Reserve)
	facades.Route().Post("/dhcp/unreserve", dhcpController.Unreserve)

	devices := controllers.NewDevicesController()
	facades.Route().Get("/devices", devices.Index)
	facades.Route().Post("/devices/code", devices.IssueCode)
	facades.Route().Post("/devices/revoke", devices.Revoke)
	facades.Route().Post("/devices/signout-others", devices.SignOutOthers)
	facades.Route().Post("/logout", devices.SignOut)

	agent := controllers.NewAgentController()
	facades.Route().Get("/agent/ping", agent.Ping)

	diagnostics := controllers.NewDiagnosticsController()
	facades.Route().Get("/diagnostics", diagnostics.Index)
	facades.Route().Post("/diagnostics/probe", diagnostics.Probe)
	facades.Route().Get("/diagnostics/probe/status", diagnostics.ProbeStatus)
	facades.Route().Post("/diagnostics/label", diagnostics.Label)
	facades.Route().Post("/diagnostics/proposal", diagnostics.Proposal)
	facades.Route().Post("/diagnostics/settings", diagnostics.Settings)
	facades.Route().Post("/diagnostics/window", diagnostics.Window)
	facades.Route().Post("/diagnostics/identify", diagnostics.IdentifyAction)
	facades.Route().Post("/diagnostics/fullcheck", diagnostics.FullCheckAction)
	supportController := controllers.NewSupportController()
	facades.Route().Post("/diagnostics/support", supportController.Collect)
	facades.Route().Get("/diagnostics/support/file", supportController.File)
	facades.Route().Get("/diagnostics/support/names", supportController.Names)
	whoami := controllers.NewWhoamiController()
	facades.Route().Get("/whoami", whoami.Show)
	facades.Route().Post("/whoami", whoami.Propose)
	facades.Route().Post("/whoami/identify", whoami.Identify)
	lantest := controllers.NewLanTestController()
	facades.Route().Get("/lantest", lantest.Show)
	facades.Route().Get("/lantest/data", lantest.Data)
	facades.Route().Post("/lantest/probe", lantest.Probe)
	facades.Route().Post("/lantest/result", lantest.Result)

	vpnController := controllers.NewVpnController()
	facades.Route().Get("/vpn", vpnController.Index)
	facades.Route().Post("/vpn/import", vpnController.Import)
	facades.Route().Post("/vpn/apply", vpnController.Apply)
	facades.Route().Post("/vpn/remove", vpnController.Remove)
	facades.Route().Post("/vpn/mtu", vpnController.MTUProbe)
	facades.Route().Post("/vpn/timesync", vpnController.TimeSync)
	facades.Route().Post("/vpn/check", vpnController.Check)
	facades.Route().Get("/vpn/check/status", vpnController.CheckStatus)
	facades.Route().Post("/vpn/probe-target", vpnController.ProbeTarget)

	securityController := controllers.NewSecurityController()
	facades.Route().Get("/security", securityController.Index)
	facades.Route().Post("/security/apply", securityController.Apply)
	facades.Route().Post("/security/updates", securityController.Updates)
	facades.Route().Post("/security/disk-change", securityController.DiskChange)
	facades.Route().Post("/security/retention", securityController.Retention)
	facades.Route().Post("/security/disk-budget", securityController.DiskBudget)
	facades.Route().Post("/security/syslog-cap", securityController.SyslogCap)
	facades.Route().Post("/security/logs-trim", securityController.LogsTrim)
	facades.Route().Post("/security/metrics-master", securityController.MetricsMaster)
	facades.Route().Post("/security/metrics-source", securityController.MetricsSource)

	network := controllers.NewNetworkController()
	facades.Route().Get("/network", network.Status)
	facades.Route().Get("/network/suggest", network.Suggest)
	facades.Route().Post("/network/apply", network.Apply)

	backupController := controllers.NewBackupController()
	facades.Route().Get("/backup", backupController.Index)
	facades.Route().Post("/backup/export/template", backupController.ExportTemplate)
	facades.Route().Post("/backup/export/copy", backupController.ExportCopy)
	facades.Route().Post("/backup/import", backupController.Upload)
	facades.Route().Get("/backup/import", backupController.Preview)
	facades.Route().Post("/backup/import/cards", backupController.Cards)
	facades.Route().Post("/backup/import/apply", backupController.Apply)
	facades.Route().Post("/backup/import/discard", backupController.Discard)
	facades.Route().Get("/backup/confirming", backupController.Confirming)
	facades.Route().Post("/backup/confirm-network", backupController.ConfirmNetwork)
	facades.Route().Post("/backup/confirm", backupController.Confirm)
	facades.Route().Post("/backup/rollback", backupController.Rollback)

	facades.Route().Get("/network/confirming", network.Confirming)
	facades.Route().Post("/network/confirm", network.Confirm)
	facades.Route().Post("/network/cancel", network.Cancel)

	metricsController := controllers.NewMetricsController()
	facades.Route().Get("/metrics/series", metricsController.Series)

	facades.Route().Static(assets.URL[1:]+"/"+assets.Fingerprint(), "./"+assets.Dir)
	facades.Route().Static(assets.Dir, "./"+assets.Dir)
}
