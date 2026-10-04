package controllers

import (
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type SetupController struct {
	service *auth.Service
	qos     *qossvc.Service
	limiter *ratelimit.Limiter
}

func NewSetupController() *SetupController {
	return &SetupController{
		service: auth.New(),
		qos:     qossvc.New(),

		limiter: ratelimit.New(5, 1, time.Minute),
	}
}

func (c *SetupController) Show(ctx contractshttp.Context) contractshttp.Response {
	if c.service.HasUsers() {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
	}
	view := map[string]any{
		"needCode": !middleware.IsLoopback(ctx.Request().Ip()),
		"error":    takeFlash(ctx, flashError),
	}

	if code := ctx.Request().Query("code"); codeInURLRe.MatchString(code) {
		view["prefillCode"] = code
	}
	return ctx.Response().View().Make("setup.tmpl", page(ctx, "Установка", "", view))
}

func (c *SetupController) Store(ctx contractshttp.Context) contractshttp.Response {
	if c.service.HasUsers() {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
	}
	ip := ctx.Request().Ip()
	if !c.limiter.Allow(ip) {
		return c.showError(ctx, "Слишком много попыток. Подождите минуту.")
	}

	if !middleware.IsLoopback(ip) && !c.service.CheckSetupCode(ctx.Request().Input("setup_code")) {
		c.service.Audit("setup_denied", nil, nil, ip, "неверный установочный код")
		return c.showError(ctx, "Код не подходит или истёк.")
	}

	name := ctx.Request().Input("name", "Администратор")
	maxUsers, err := strconv.Atoi(ctx.Request().Input("max_users", "1"))
	if err != nil {
		return c.showError(ctx, "Число учётных записей укажите цифрами.")
	}

	if _, err := auth.Edit(func(s *auth.Section) error { s.MaxUsers = maxUsers; return nil }); err != nil {
		return c.showError(ctx, "Настройки не сохранены: "+err.Error()+".")
	}
	user, err := c.service.CreateUser(name)
	if err != nil {
		return c.showError(ctx, "Не удалось создать учётную запись.")
	}
	token, device, err := c.service.EnrollConsoleDevice(user.ID,
		ctx.Request().Input("device_label", "Компьютер установки"),
		ctx.Request().Header("User-Agent"), ip)
	if err != nil {
		return c.showError(ctx, "Не удалось доверить это устройство.")
	}
	c.service.ClearSetupCode()
	c.service.Audit("setup_completed", &user.ID, &device.ID, ip, "мастер завершён")

	setDeviceCookie(ctx, token)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/speed")
}

func (c *SetupController) SpeedShow(ctx contractshttp.Context) contractshttp.Response {
	view := map[string]any{
		"error": takeFlash(ctx, flashError),
		"ok":    takeFlash(ctx, flashCode),
	}
	addSpeedtestView(view, c.qos.Speedtest())
	view["speedBack"] = "/setup/speed"
	if _, ok := view["measureDownMbit"]; !ok {
		if down, up := c.qos.MeasuredMbit(); down > 0 {
			view["measureDownMbit"] = down
			view["measureUpMbit"] = up
		}
	}
	return ctx.Response().View().Make("setup_speed.tmpl", page(ctx, "Установка: скорость интернета", "", view))
}

func (c *SetupController) SpeedStore(ctx contractshttp.Context) contractshttp.Response {
	downMbit, derr := strconv.Atoi(ctx.Request().Input("down_mbit"))
	upMbit, uerr := strconv.Atoi(ctx.Request().Input("up_mbit"))
	if derr != nil || uerr != nil {
		setFlash(ctx, flashError, "Укажите обе скорости числом в Мбит/с — проще всего нажать «Запустить замер» и затем «Подставить».")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/speed")
	}

	if _, err := qossvc.Edit(func(s *qossvc.Section) error {
		s.Enabled, s.DownKbit, s.UpKbit = true, downMbit*1000, upMbit*1000
		return nil
	}); err != nil {
		setFlash(ctx, flashError, err.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/speed")
	}
	setFlash(ctx, flashCode, "Приоритет телефонии настроен и включится автоматически после настройки сети. Теперь назначьте роли сетевых карт.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/network")
}

func (c *SetupController) showError(ctx contractshttp.Context, msg string) contractshttp.Response {
	setFlash(ctx, flashError, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
}

func clearDeviceCookie(ctx contractshttp.Context) {
	ctx.Response().Cookie(contractshttp.Cookie{
		Name: auth.DeviceCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: "Strict",
	})
}

func setDeviceCookie(ctx contractshttp.Context, token string) {
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     auth.DeviceCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int((14 * 24 * time.Hour).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
	})
}
