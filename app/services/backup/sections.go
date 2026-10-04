package backup

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

func Sections() []Entry {
	net := []settings.Section{settings.SectionNetwork}
	return []Entry{
		Of(Def[network.Section]{Name: settings.SectionNetwork, Version: 1,
			Read: network.ReadSection, Validate: alone(network.ValidateSection), Apply: anyone(network.ApplySection)}),
		Of(Def[security.Section]{Name: settings.SectionSecurity, Version: 1, After: net,
			Read: security.ReadSection, Validate: alone(security.ValidateSection),
			Apply: anyone(security.ApplySection)}),
		Of(Def[dhcp.Section]{Name: settings.SectionDHCP, Version: 1, After: net,
			Read: dhcp.ReadSection, Validate: validateDHCP, Apply: anyone(dhcp.ApplySection)}),
		Of(Def[qos.Section]{Name: settings.SectionQoS, Version: 1, After: net,
			Read: qos.ReadSection, Validate: alone(qos.ValidateSection),
			Apply: anyone(qos.ApplySection)}),
		Of(Def[vpn.Section]{Name: settings.SectionVPN, Version: 1,
			After: []settings.Section{settings.SectionNetwork, settings.SectionSecurity},
			Read:  vpn.ReadSection, Validate: alone(vpn.ValidateSection), Apply: anyone(vpn.ApplySection)}),
		Of(Def[diag.LabelsSection]{Name: settings.SectionDevices, Version: 1,
			Read: diag.ReadLabelsSection, Validate: alone(diag.ValidateLabelsSection),
			Apply: anyone(diag.ApplyLabelsSection)}),
		Of(Def[diag.Section]{Name: settings.SectionDiag, Version: 1,
			Read: diag.ReadSection, Validate: alone(diag.ValidateSection),
			Apply: anyone(diag.ApplySection)}),
		Of(Def[retention.Section]{Name: settings.SectionRetention, Version: 1,
			Read: retention.ReadSection, Validate: alone(retention.ValidateSection),
			Apply: anyone(retention.ApplySection)}),
		Of(Def[metrics.Section]{Name: settings.SectionMetrics, Version: 1,
			Read: metrics.ReadSectionForCopy, Validate: alone(metrics.ValidateSection),
			Apply: metrics.ApplySection}),
		Of(Def[auth.Section]{Name: settings.SectionAuth, Version: 1,
			Read: auth.ReadSection, Validate: alone(auth.ValidateSection),
			Apply: anyone(auth.ApplySection)}),
	}
}

func alone[T any](f func(T) fielderr.List) func(T, Desired) fielderr.List {
	return func(v T, _ Desired) fielderr.List { return f(v) }
}

func anyone[T any](f func(cur, want T) error) func(T, T, string) error {
	return func(cur, want T, _ string) error { return f(cur, want) }
}

func validateDHCP(v dhcp.Section, d Desired) fielderr.List {
	n, _ := DesiredOf[network.Section](d, settings.SectionNetwork)
	return dhcp.ValidateSection(v, n.LANs())
}
