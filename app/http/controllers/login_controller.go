package controllers

import (
	"regexp"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

var codeInURLRe = regexp.MustCompile(`^[23456789ABCDEFGHJKMNPQRSTWXYZ]{4}-[23456789ABCDEFGHJKMNPQRSTWXYZ]{4}$`)

const desktopDeviceLabel = "Рабочий стол сервера"

type LoginController struct {
	service *auth.Service
	limiter *ratelimit.Limiter
}

func NewLoginController() *LoginController {
	return &LoginController{
		service: auth.New(),
		limiter: ratelimit.New(5, 1, time.Minute),
	}
}

func (c *LoginController) Show(ctx contractshttp.Context) contractshttp.Response {
	if !c.service.HasUsers() {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	view := map[string]any{
		"error": takeFlash(ctx, flashError),

		"onServer": middleware.IsLoopback(ctx.Request().Ip()),
	}

	if code := ctx.Request().Query("code"); codeInURLRe.MatchString(code) {
		view["prefillCode"] = code
		view["deviceLabel"] = desktopDeviceLabel
		view["autoLogin"] = true
	} else if middleware.IsLoopback(ctx.Request().Ip()) {

		view["desktopHint"] = true
	}
	return ctx.Response().View().Make("login.tmpl", page(ctx, "Вход", "", view))
}

func (c *LoginController) Enter(ctx contractshttp.Context) contractshttp.Response {
	if !c.service.HasUsers() {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	ip := ctx.Request().Ip()
	if !c.limiter.Allow(ip) {
		return c.showError(ctx, "Слишком много попыток. Подождите минуту.")
	}
	token, _, err := c.service.UseCode(
		ctx.Request().Input("code"),
		ctx.Request().Input("device_label"),
		ctx.Request().Header("User-Agent"), ip)
	if err != nil {

		return c.showError(ctx, "Код не подходит или истёк.")
	}
	setDeviceCookie(ctx, token)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/")
}

func (c *LoginController) showError(ctx contractshttp.Context, msg string) contractshttp.Response {
	setFlash(ctx, flashError, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
}
