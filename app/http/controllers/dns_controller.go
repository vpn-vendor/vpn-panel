package controllers

import (
	contractshttp "github.com/goravel/framework/contracts/http"

	dnssvc "github.com/vpn-vendor/vpn-panel-core/app/services/dns"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

type DnsController struct {
	service *dnssvc.Service
}

func NewDnsController() *DnsController {
	return &DnsController{service: dnssvc.New()}
}

func (c *DnsController) Index(ctx contractshttp.Context) contractshttp.Response {
	plan := c.service.BuildPlan()
	view := map[string]any{
		"error":    takeFlash(ctx, flashError),
		"ok":       takeFlash(ctx, flashCode),
		"domain":   unboundgen.LocalDomain,
		"upstream": unboundgen.Upstream,
		"ready":    c.service.Ready(),
	}
	var notices []notice
	if len(plan.Segments) == 0 {
		notices = append(notices, notice{Level: "warn",
			Text: "Локальная сеть ещё не настроена: назначьте карте роль «локальная сеть» на странице «Сеть», и разрешение имён включится автоматически."})
	} else {
		view["addresses"] = plan.ListenAddresses()
		view["segments"] = plan.Segments
		if !c.service.Ready() {
			notices = append(notices, notice{Level: "warn",
				Text: "Локальное разрешение имён ещё не подтверждено: устройствам офиса выдаются публичные серверы имён. Примените настройки сети ещё раз на странице «Сеть»."})
		}
	}
	view["notices"] = notices
	return ctx.Response().View().Make("dns.tmpl", page(ctx, "DNS", "dns", view))
}
