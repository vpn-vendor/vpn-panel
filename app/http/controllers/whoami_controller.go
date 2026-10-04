package controllers

import (
	"net"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

type WhoamiController struct {
	service  *diag.Service
	limiter  *ratelimit.Limiter
	attempts *ratelimit.Limiter
}

func NewWhoamiController() *WhoamiController {

	return &WhoamiController{service: diag.New(),
		limiter: ratelimit.New(3, 3, time.Minute), attempts: ratelimit.New(20, 20, time.Minute)}
}

func IsShortHost(host string) bool { return middleware.IsShortHost(host) }

func (c *WhoamiController) Show(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	view := map[string]any{
		"title":     "Это я",
		"error":     takeFlash(ctx, flashError),
		"ok":        takeFlash(ctx, flashCode),
		"ip":        ip,
		"selfLabel": c.service.Settings().SelfLabel,
		"shortName": unboundgen.ShortNames[0],
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		view["loopback"] = true
	} else {
		id := c.service.Identify(ip)
		view["found"] = id.Found
		view["mac"] = id.MAC
		view["hostname"] = id.Hostname
		view["vendor"] = id.Vendor
		view["label"] = diag.VisibleLabel(id.Record)
		view["proposed"] = joinNonEmpty(id.Record.ProposedLabel, id.Record.ProposedLocation, id.Record.ProposedOwner)
		if id.Record.IdentifyRequestedAt != nil {
			view["identifyAt"] = id.Record.IdentifyRequestedAt.Local().Format("02.01.2006 15:04:05")
		}
		view["number"] = id.Record.ID
	}
	return ctx.Response().View().Make("whoami.tmpl", withCsrf(ctx, view))
}

func (c *WhoamiController) Propose(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	back := "/whoami"
	if IsShortHost(ctx.Request().Host()) {
		back = "/"
	}
	if !c.attempts.Allow(ip) {
		c.service.Audit("device_label_throttled", ip, "слишком частые попытки предложить подпись")
		setFlash(ctx, flashError, "Слишком много попыток. Подождите минуту и попробуйте снова.")
		return ctx.Response().Redirect(contractshttp.StatusFound, back)
	}
	label, location, owner := ctx.Request().Input("label"), ctx.Request().Input("location"), ctx.Request().Input("owner")

	if text := diag.PreviewProposal(label, location, owner); text != "" {
		setFlash(ctx, flashError, "Предложение не отправлено: "+text)
		return ctx.Response().Redirect(contractshttp.StatusFound, back)
	}
	if !c.limiter.Allow(ip) {
		c.service.Audit("device_label_throttled", ip, "слишком частые предложения подписи")
		setFlash(ctx, flashError, "Предложение уже отправлялось несколько раз подряд — подождите немного и попробуйте снова.")
		return ctx.Response().Redirect(contractshttp.StatusFound, back)
	}
	id := c.service.Identify(ip)
	err := c.service.Propose(id, label, location, owner)
	if err != nil {
		setFlash(ctx, flashError, "Предложение не отправлено: "+err.Error())
	} else {
		setFlash(ctx, flashCode, "Спасибо! Предложение отправлено администратору — после проверки оно станет подписью устройства.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, back)
}

func (c *WhoamiController) Identify(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	back := "/whoami"
	if IsShortHost(ctx.Request().Host()) {
		back = "/"
	}
	if !c.attempts.Allow(ip) || !c.limiter.Allow(ip) {
		c.service.Audit("device_label_throttled", ip, "слишком частые сообщения администратору")
		setFlash(ctx, flashError, "Сообщение уже отправлялось несколько раз подряд — подождите немного.")
		return ctx.Response().Redirect(contractshttp.StatusFound, back)
	}
	id := c.service.Identify(ip)
	if err := c.service.RequestIdentify(id, ctx.Request().Input("note")); err != nil {
		setFlash(ctx, flashError, "Сообщение не отправлено: "+err.Error())
	} else {
		setFlash(ctx, flashCode, "Администратор получил сообщение: он увидит этот компьютер в списке и подпишет его.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, back)
}
