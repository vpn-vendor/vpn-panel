package controllers

import (
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type LanTestController struct {
	service *diag.Service
	limiter *ratelimit.Limiter

	logOnce *ratelimit.Limiter
	chunk   []byte
}

const (
	lanQuickSeconds = 3
	lanQuickMbit    = 150
	lanFullSeconds  = 5
	lanFullMbitCap  = 1200
	lanChunkBytes   = 256 * 1024
	lanCPUMaxBusy   = 70.0
)

func NewLanTestController() *LanTestController {
	chunk := make([]byte, lanChunkBytes)
	_, _ = rand.Read(chunk)
	return &LanTestController{service: diag.New(), limiter: ratelimit.New(2, 1, time.Minute), logOnce: ratelimit.New(1, 1, time.Minute), chunk: chunk}
}

func (c *LanTestController) Show(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	win := c.service.Window().State()
	full := c.service.FullCheck().State()
	view := map[string]any{"title": "Скорость до сервера", "ip": ip, "activeProbes": c.service.Settings().ActiveProbes,
		"windowOpen": (win.Open || full.Active) && c.service.Settings().ActiveProbes, "fullAllowed": win.FullAllowed || full.Active,
		"windowUntil": win.Until.Local().Format("02.01.2006 15:04:05"),
		"fullCheck":   full.Active, "fullCheckUntil": full.Until.Local().Format("02.01.2006 15:04:05")}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		view["loopback"] = true
	} else {
		id := c.service.Identify(ip)
		view["found"] = id.Found
		view["hostname"] = id.Hostname
		if id.Record.LanTestedAt != nil && id.Record.LanMbit > 0 {
			view["lastMbit"] = id.Record.LanMbit
			view["lastAt"] = id.Record.LanTestedAt.Local().Format("02.01.2006 15:04:05")
		}
	}
	return ctx.Response().View().Make("lantest.tmpl", withCsrf(ctx, view))
}

func (c *LanTestController) Data(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	mode := ctx.Request().Input("mode", "quick")

	if !c.service.Settings().ActiveProbes {
		return ctx.Response().String(contractshttp.StatusForbidden, "проверки скорости выключены администратором")
	}

	if c.service.FullCheck().State().Active {
		seconds, mbit := lanQuickSeconds, lanQuickMbit
		if mode == "full" {
			seconds, mbit = lanFullSeconds, lanFullMbitCap
		}
		_ = seconds
		if c.logOnce.Allow("full:" + ip) {
			id := c.service.Identify(ip)
			c.service.Audit("diag_lantest_started", ip, "полная проверка, режим "+lanModeName(mode)+", MAC "+id.MAC+", "+id.Hostname)
		}
		_ = mbit
		ctx.Response().Header("Cache-Control", "no-store")
		return ctx.Response().Data(contractshttp.StatusOK, "application/octet-stream", c.chunk)
	}
	win := c.service.Window().State()
	if !win.Open {
		return ctx.Response().String(contractshttp.StatusForbidden, "окно проверок закрыто — попросите администратора открыть его на странице «Диагностика»")
	}
	seconds, mbit := lanQuickSeconds, lanQuickMbit
	if mode == "full" {
		if !win.FullAllowed {
			return ctx.Response().String(contractshttp.StatusForbidden, "полный замер в этом окне не разрешён администратором")
		}
		seconds, mbit = lanFullSeconds, lanFullMbitCap
	}
	fresh, err := diag.LanTestSession(ip, time.Duration(seconds)*time.Second)
	if err != nil {
		code := contractshttp.StatusConflict
		if errors.Is(err, diag.ErrLanTestCooldown) {
			code = contractshttp.StatusTooManyRequests
		}
		return ctx.Response().String(code, err.Error())
	}
	if fresh {
		if !c.limiter.Allow("data:" + ip) {
			return ctx.Response().String(contractshttp.StatusTooManyRequests, "слишком часто — подождите минуту")
		}

		if refuse := lanProtectionRefusal(mode); refuse != "" {
			return ctx.Response().String(contractshttp.StatusServiceUnavailable, refuse)
		}

		id := c.service.Identify(ip)
		c.service.Audit("diag_lantest_started", ip, "режим "+lanModeName(mode)+", MAC "+id.MAC+", "+id.Hostname)
	}
	bytesPerSec := float64(mbit) * 1000 * 1000 / 8
	if wait := diag.LanTestPace(len(c.chunk), bytesPerSec); wait > 0 {
		time.Sleep(wait)
	}
	ctx.Response().Header("Cache-Control", "no-store")
	return ctx.Response().Data(contractshttp.StatusOK, "application/octet-stream", c.chunk)
}

func lanProtectionRefusal(mode string) string {
	col := metrics.Current()
	if col == nil {
		if mode == "full" {
			return "сбор показателей ещё не запущен — полный замер пока отказан"
		}
		return ""
	}
	p := col.Protection()
	if !p.OK {
		if mode == "full" {
			return "датчики защиты сервера без свежих данных — полный замер отказан"
		}
		return ""
	}
	if p.CPUBusy > lanCPUMaxBusy {
		return "сервер занят (процессор " + strconv.FormatFloat(p.CPUBusy, 'f', 0, 64) + " %) — повторите позже"
	}
	return ""
}

func lanModeName(mode string) string {
	if mode == "full" {
		return "полный"
	}
	return "быстрый"
}

func (c *LanTestController) Probe(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	if !c.limiter.Allow("probe:" + ip) {
		return ctx.Response().Json(contractshttp.StatusTooManyRequests, map[string]any{"error": "слишком часто"})
	}
	res, err := c.service.ProbeOne(ip)
	if err != nil {
		return ctx.Response().Json(contractshttp.StatusOK, map[string]any{"error": err.Error()})
	}
	return ctx.Response().Json(contractshttp.StatusOK, map[string]any{
		"avg_ms": res.AvgMs, "max_ms": res.MaxMs, "jitter_ms": res.JitterMs, "loss": res.LossPercent(),
	})
}

func (c *LanTestController) Result(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	mbit, _ := strconv.Atoi(ctx.Request().Input("mbit"))
	idle, _ := strconv.ParseFloat(ctx.Request().Input("idle_ms"), 64)
	load, _ := strconv.ParseFloat(ctx.Request().Input("load_ms"), 64)

	if mbit <= 0 || mbit > 100000 || idle < 0 || load < 0 || idle > 10000 || load > 10000 {
		return ctx.Response().Json(contractshttp.StatusBadRequest, map[string]any{"error": "неверные данные"})
	}

	if throttled, _ := diag.LanTestThrottled(ip); throttled {
		return ctx.Response().Json(contractshttp.StatusOK, map[string]any{"ok": true, "verdict": lanThrottledVerdict})
	}
	id := c.service.Identify(ip)
	if err := c.service.SaveLanTest(id, mbit, idle, load); err != nil {
		return ctx.Response().Json(contractshttp.StatusOK, map[string]any{"error": err.Error()})
	}
	verdict := lanVerdict(ctx.Request().Input("mode", "quick"), mbit, idle, load)
	return ctx.Response().Json(contractshttp.StatusOK, map[string]any{"ok": true, "verdict": verdict})
}

const lanThrottledVerdict = "Замер недействителен: во время проверки сервер упёрся в свой предел процессора, и скорость ограничил он, а не сеть. Результат не сохранён — повторите проверку позже."

func lanVerdict(mode string, mbit int, idle, load float64) string {
	queue := ""
	if load > 0 && idle > 0 && load-idle >= 10 {
		queue = " Под нагрузкой задержка выросла с " + strconv.FormatFloat(idle, 'f', 1, 64) + " до " + strconv.FormatFloat(load, 'f', 1, 64) + " мс — на пути очередь (коммутатор или роутер с малым буфером); умная очередь сервера здесь бессильна, замените узел."
	}
	switch {
	case mbit < 80:
		return "Скорость до сервера ниже 80 Мбит/с — на пути к этому компьютеру медленный узел или Wi-Fi. Проверьте кабель, порт коммутатора и режим подключения." + queue
	case mbit <= 100:
		return "Около 100 Мбит/с: на пути к этому компьютеру узел на 100 Мбит/с (коммутатор, 4-жильный кабель или роутер). Для телефонии этого достаточно, но большие закачки будут создавать очередь — замените узел на гигабитный." + queue
	case mode != "full":
		return "Узла на 100 Мбит/с на пути нет. Быстрая проверка ограничена сверху — точную скорость покажет полный замер в нерабочее время." + queue
	case mbit < 300:
		return "Быстрее 100 Мбит/с, но ниже гигабита — возможно Wi-Fi или ограничение узла на пути." + queue
	}
	if queue != "" {
		return "Скорость гигабитная." + queue
	}
	return "Путь до сервера гигабитный, без очередей — узких мест внутри офиса на этом пути нет."
}
