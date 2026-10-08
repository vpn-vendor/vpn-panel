package controllers

import (
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
)

type HomeController struct {
	whoami *WhoamiController
}

func NewHomeController() *HomeController { return &HomeController{whoami: NewWhoamiController()} }

func (c *HomeController) Index(ctx contractshttp.Context) contractshttp.Response {
	if IsShortHost(ctx.Request().Host()) {
		return c.whoami.Show(ctx)
	}

	f := setup.Collect(setup.Deps{})
	plan := wizard.Plan(f.Wizard())
	if !f.Finished && !f.RolesApplied && plan.Current != nil {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	data := page(ctx, "Обзор", "home", overviewView(gatherOverview()))

	notices, _ := data["notices"].([]notice)

	if !f.Finished && f.RolesApplied && plan.Current != nil && plan.Current.Key != "check" {
		notices = append(notices, notice{Level: "warn",
			Text:       "Первая настройка не завершена — остался шаг «" + plan.Current.Title + "» (" + strconv.Itoa(plan.Done+1) + " из " + strconv.Itoa(plan.Total) + ").",
			ActionURL:  "/setup",
			ActionText: "Продолжить настройку"})
	}

	if reliability.FirstDay(time.Now()) {
		notices = append(notices, notice{Level: "info", Text: "Первые сутки работы шлюза: держите прежний роутер под рукой. Если офис останется без связи — переставьте кабель провайдера обратно в прежний роутер, и сеть заработает как раньше. Сделайте копию настроек на странице «Резервная копия»."})
	}
	for _, n := range restore.Live().Notices() {
		notices = append(notices, notice{Level: n.Level, Text: n.Text})
	}
	data["notices"] = notices
	return ctx.Response().View().Make("overview.tmpl", data)
}

func (c *HomeController) Health(ctx contractshttp.Context) contractshttp.Response {

	return ctx.Response().Success().Json(contractshttp.Json{
		"ok": true,
	})
}
