package controllers

import (
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
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
	for _, n := range restore.Live().Notices() {
		notices = append(notices, notice{Level: n.Level, Text: n.Text})
	}
	notices = append(notices, systemNotices(system.New().Report(time.Now()))...)
	if around, err := system.New().Surroundings(); err == nil {
		around = holdSeen(around, system.LastSeen())
		notices = append(notices, surroundNotices(withOwnBinding(around, panelInUse(), time.Now()))...)
	}
	data["notices"] = notices
	return ctx.Response().View().Make("overview.tmpl", data)
}

func (c *HomeController) Health(ctx contractshttp.Context) contractshttp.Response {

	return ctx.Response().Success().Json(contractshttp.Json{
		"ok": true,
	})
}

func (c *HomeController) Feed(ctx contractshttp.Context) contractshttp.Response {
	after, _ := strconv.ParseUint(ctx.Request().Query("after"), 10, 64)

	rows := recentEvents(feedCap, uint(after))
	out := make([]contractshttp.Json, 0, len(rows))
	last := uint(after)
	for _, e := range rows {
		ev := feedEvent(e)
		out = append(out, contractshttp.Json{"id": ev.ID, "time": ev.Time, "title": ev.Title, "detail": ev.Detail, "level": string(ev.Level)})
		if ev.ID > last {
			last = ev.ID
		}
	}
	return ctx.Response().Success().Json(contractshttp.Json{"events": out, "after": last})
}
