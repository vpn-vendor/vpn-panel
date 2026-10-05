package controllers

import (
	"fmt"
	"time"

	"errors"
	"strconv"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
)

type DevicesController struct {
	service *auth.Service
}

func NewDevicesController() *DevicesController {
	return &DevicesController{service: auth.New()}
}

type deviceView struct {
	ID         uint
	Label      string
	UserAgent  string
	LastIP     string
	LastUsed   string
	Created    string
	Main       bool
	Quarantine bool
	Revoked    bool
	Current    bool
}

type eventView struct {
	When    string
	Event   string
	IP      string
	Details string
	Repeats string
}

func repeatsText(count int, last *time.Time) string {
	if count <= 0 {
		return ""
	}
	text := fmt.Sprintf("повторялось ещё %d раз", count)
	if last != nil {
		text += ", последний раз " + last.Format("02.01.2006 15:04:05")
	}
	return text
}

func actor(ctx contractshttp.Context) *models.TrustedDevice {
	d, _ := ctx.Value(middleware.CtxDevice).(*models.TrustedDevice)
	return d
}

func (c *DevicesController) Index(ctx contractshttp.Context) contractshttp.Response {
	return c.render(ctx, takeFlash(ctx, flashCode), takeFlash(ctx, flashError), takeFlash(ctx, flashDone))
}

func (c *DevicesController) IssueCode(ctx contractshttp.Context) contractshttp.Response {
	a := actor(ctx)
	code, err := c.service.IssueCode(a.UserID, auth.ViaDevice, a, ctx.Request().Ip())
	if err != nil {
		setFlash(ctx, flashError, humanAuthError(err))
	} else {
		setFlash(ctx, flashCode, code)
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
}

func (c *DevicesController) SignOut(ctx contractshttp.Context) contractshttp.Response {
	a := actor(ctx)
	if err := c.service.SignOut(a, ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, "Выйти не удалось. Попробуйте ещё раз.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
	}
	clearDeviceCookie(ctx)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
}

func (c *DevicesController) SignOutOthers(ctx contractshttp.Context) contractshttp.Response {
	n, err := c.service.SignOutOthers(actor(ctx), ctx.Request().Ip())
	switch {
	case errors.Is(err, auth.ErrNotMain):
		setFlash(ctx, flashError, "Выйти на остальных устройствах может только главное устройство — подключённое с самого сервера. Полный сброс — с консоли сервера.")
	case err != nil:
		setFlash(ctx, flashError, humanAuthError(err))
	case n == 0:
		setFlash(ctx, flashDone, "Других действующих устройств нет — выводить некого.")
	default:
		setFlash(ctx, flashDone, "Выход выполнен на "+ui.Plural(n, "устройстве", "устройствах", "устройствах")+". Снова войти с выведенных устройств можно только по новому коду подключения.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
}

func (c *DevicesController) Revoke(ctx contractshttp.Context) contractshttp.Response {
	a := actor(ctx)

	id, err := strconv.ParseUint(ctx.Request().Input("device_id"), 10, strconv.IntSize)
	if err != nil {
		setFlash(ctx, flashError, "Устройство не найдено.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
	}
	if err := c.service.Revoke(a, uint(id), ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, humanAuthError(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
	}
	if uint(id) == a.ID {
		clearDeviceCookie(ctx)
		return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/devices")
}

func (c *DevicesController) render(ctx contractshttp.Context, freshCode, errMsg, done string) contractshttp.Response {
	a := actor(ctx)
	devices := c.service.Devices(a.UserID)

	now, sliding := time.Now(), c.service.Sliding()
	views := make([]deviceView, 0, len(devices))
	dead := 0
	for _, d := range devices {
		if !auth.Alive(d, now, sliding) {
			dead++
			continue
		}
		views = append(views, deviceView{
			ID:         d.ID,
			Label:      d.Label,
			UserAgent:  shorten(d.UserAgent, 60),
			LastIP:     d.LastIP,
			LastUsed:   d.LastUsedAt.Format("02.01.2006 15:04"),
			Created:    d.CreatedAt.Format("02.01.2006 15:04"),
			Main:       d.EnrolledVia == auth.ViaConsole,
			Quarantine: c.service.InQuarantine(&d),
			Revoked:    d.RevokedAt != nil,
			Current:    d.ID == a.ID,
		})
	}
	events := make([]eventView, 0, 30)
	for _, e := range c.service.RecentEvents(30) {
		events = append(events, eventView{
			When:    e.OccurredAt.Format("02.01.2006 15:04:05"),
			Event:   eventTitle(e.Event),
			IP:      e.IP,
			Details: e.Details,
			Repeats: repeatsText(e.RepeatCount, e.LastAt),
		})
	}
	return ctx.Response().View().Make("devices.tmpl", page(ctx, "Устройства", "devices", map[string]any{
		"devices":      views,
		"events":       events,
		"freshCode":    freshCode,
		"error":        errMsg,
		"done":         done,
		"inQuarantine": c.service.InQuarantine(a),
		"codeTTL":      c.service.SettingInt(auth.SettingCodeTTLMinutes),
		"slidingHours": c.service.SettingInt(auth.SettingSlidingHours),
		"absoluteDays": c.service.SettingInt(auth.SettingAbsoluteDays),
		"deadCount":    dead,
		"trustDays":    retention.Load().TrustDays,
		"canSignOut":   a.EnrolledVia == auth.ViaConsole && !c.service.InQuarantine(a),
		"aliveCount":   len(views),
	}))
}

func humanAuthError(err error) string {
	if errors.Is(err, auth.ErrQuarantined) {
		return "Это устройство добавлено недавно: первые часы оно не может приглашать другие и отзывать доступ."
	}
	return "Действие не выполнено. Попробуйте ещё раз."
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
