package controllers

import (
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/support"
)

type SupportController struct {
	service *support.Service
}

func NewSupportController() *SupportController {
	return &SupportController{service: &support.Service{
		Template: func() ([]byte, error) { return restore.Live().ExportTemplate() },
	}}
}

type supportRow struct {
	Alias, Label string
}

func (c *SupportController) view(view map[string]any) {
	st, err := c.service.State()
	if err != nil {
		return
	}
	view["supportRunning"] = st.Running()
	view["supportFailed"] = st.Failed()
	if st.Ready() {
		view["supportReady"] = true
		view["supportSize"] = bytesText(st.Bytes)
		view["supportAt"] = time.Unix(st.At, 0).Local().Format("02.01.2006 15:04")
	}
}

func (c *SupportController) Collect(ctx contractshttp.Context) contractshttp.Response {
	if err := c.service.Collect(); err != nil {
		setFlash(ctx, flashError, "Сведения не собираются: "+errText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics#support")
	}
	securitylog.Record(models.AuthEvent{Event: "support_collected", IP: ctx.Request().Ip(),
		Details: "собран файл сведений для поддержки", OccurredAt: time.Now()})
	setFlash(ctx, flashCode, "Сведения собираются. Через минуту обновите страницу — появится ссылка на файл.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics#support")
}

func (c *SupportController) File(ctx contractshttp.Context) contractshttp.Response {
	name, data, err := c.service.File()
	if err != nil {
		setFlash(ctx, flashError, "Файл сведений не готов — соберите его заново.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics#support")
	}
	return attachment(ctx, name, "application/octet-stream", data)
}

func (c *SupportController) Names(ctx contractshttp.Context) contractshttp.Response {
	view := map[string]any{}
	rows, err := c.service.Decode()
	if err != nil {
		view["error"] = "Условные имена не получены: " + errText(err)
	}
	out := make([]supportRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, supportRow{Alias: r.Alias, Label: r.Label})
	}
	view["rows"] = out
	return ctx.Response().View().Make("support_names.tmpl", page(ctx, "Условные имена устройств", "diagnostics", view))
}
