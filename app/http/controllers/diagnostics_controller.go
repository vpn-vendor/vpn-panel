package controllers

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/oui"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type DiagnosticsController struct {
	service *diag.Service

	window *ratelimit.Limiter
}

func NewDiagnosticsController() *DiagnosticsController {
	return &DiagnosticsController{service: diag.New(), window: ratelimit.New(6, 1, time.Minute)}
}

type deviceRow struct {
	MAC, IP, Hostname, Vendor string
	Label, Location, Owner    string
	Note                      string
	LabelSource               string
	Level                     string
	Managed, Online           bool
	RandomMAC                 bool
	FirstSeen, LastSeen       string
	Diagnoses                 []diagnosisRow
	ProbeText                 string
	LanText                   string
	HasProposal               bool
	PublicLabel               string
	Preview                   string
	Legacy                    bool
	Proposed                  string
}

type diagnosisRow struct {
	Level, Title, Advice, Confidence string
}

type proposalRow struct {
	MAC, Hostname, IP, Text, When string
}

func (c *DiagnosticsController) Index(ctx contractshttp.Context) contractshttp.Response {
	view := map[string]any{
		"error": takeFlash(ctx, flashError),
		"ok":    takeFlash(ctx, flashCode),
	}
	settings := c.service.Settings()
	view["activeProbes"] = settings.ActiveProbes
	view["selfLabel"] = settings.SelfLabel
	c.windowView(view)
	c.fullCheckView(view)
	view["ouiUpdated"] = oui.Updated()
	var notices []notice

	if len(c.service.LANs()) == 0 {
		notices = append(notices, notice{Level: "info",
			Text: "Диагностика заработает после назначения роли «локальная сеть» на странице «Сеть»."})
	}

	report, rows, err := c.service.Report()
	switch err {
	case nil:
		devices := make([]deviceRow, 0, len(rows))
		for _, r := range rows {
			devices = append(devices, toDeviceRow(r))
		}
		view["devices"] = devices
		network := make([]diagnosisRow, 0, len(report.Network))
		for _, d := range report.Network {
			network = append(network, diagnosisRow{Level: d.Level, Title: d.Title, Advice: d.Advice, Confidence: d.Confidence})
		}
		view["network"] = network
		view["level"] = report.Level
		st := c.service.ProbeState()
		view["probeRunning"] = st.Running
		if st.Error != "" {
			notices = append(notices, notice{Level: "error", Text: "Последняя проверка сети не удалась: " + st.Error})
		}
		snap := c.service.LastProbe()
		if !snap.At.IsZero() {
			view["probedAt"] = snap.At.Local().Format("02.01.2006 15:04")
			if snap.Partial {
				notices = append(notices, notice{Level: "warn",
					Text: "Последняя проверка сети не успела опросить все устройства за отведённое время — часть строк без результата. Повторите проверку."})
			}
		}
	default:
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			view["agentDown"] = true
		} else {
			notices = append(notices, notice{Level: "error", Text: network.ErrText(err)})
		}
	}

	proposals := c.service.Proposals()
	prows := make([]proposalRow, 0, len(proposals))
	for _, p := range proposals {
		when := ""
		if p.ProposedAt != nil {
			when = p.ProposedAt.Local().Format("02.01 15:04")
		}
		prows = append(prows, proposalRow{MAC: p.MAC, Hostname: p.Hostname, IP: p.ProposedIP,
			Text: joinNonEmpty(p.ProposedLabel, p.ProposedLocation, p.ProposedOwner), When: when})
	}
	view["proposals"] = prows
	c.identifyView(view)
	if len(prows) > 0 {
		notices = append(notices, notice{Level: "info",
			Text: fmt.Sprintf("Сотрудники предложили подписи для %d устройств — проверьте и примите их в разделе «Предложения подписей».", len(prows))})
	}
	view["notices"] = notices
	NewSupportController().view(view)
	return ctx.Response().View().Make("diagnostics.tmpl", page(ctx, "Диагностика", "diagnostics", view))
}

func toDeviceRow(r diag.Row) deviceRow {
	row := deviceRow{
		MAC: r.MAC, IP: r.IP, Hostname: r.Hostname, Vendor: r.Vendor,
		Label: r.Record.Label, Location: r.Record.Location, Owner: r.Record.Owner, Note: r.Record.Note,
		PublicLabel: r.Record.PublicLabel, Preview: diag.VisibleLabel(r.Record), Legacy: r.Record.LabelReviewedAt == nil && r.Record.PublicLabel == "",
		LabelSource: r.Record.LabelSource, Level: r.Level, Managed: r.Managed, Online: r.Online, RandomMAC: r.RandomMAC,
		FirstSeen:   r.Record.FirstSeenAt.Local().Format("02.01.2006"),
		LastSeen:    r.Record.LastSeenAt.Local().Format("02.01 15:04"),
		HasProposal: r.Record.ProposedAt != nil,
		Proposed:    joinNonEmpty(r.Record.ProposedLabel, r.Record.ProposedLocation, r.Record.ProposedOwner),
	}
	for _, d := range r.Diagnoses {
		row.Diagnoses = append(row.Diagnoses, diagnosisRow{Level: d.Level, Title: d.Title, Advice: d.Advice, Confidence: d.Confidence})
	}
	if r.Probe != nil {
		if r.Probe.Received == 0 {
			row.ProbeText = "не ответило"
		} else {
			row.ProbeText = fmt.Sprintf("потери %d %%, задержка %.1f мс, разброс %.1f мс", r.Probe.LossPercent(), r.Probe.AvgMs, r.Probe.JitterMs)
		}
	}
	if r.Record.LanTestedAt != nil && r.Record.LanMbit > 0 {
		row.LanText = fmt.Sprintf("%d Мбит/с (%s)", r.Record.LanMbit, r.Record.LanTestedAt.Local().Format("02.01"))
		if r.Record.LanLoadMs > 0 {
			row.LanText += fmt.Sprintf(", задержка %.1f → %.1f мс под нагрузкой", r.Record.LanIdleMs, r.Record.LanLoadMs)
		}
	}
	return row
}

func joinNonEmpty(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += p
	}
	return out
}

func (c *DiagnosticsController) Probe(ctx contractshttp.Context) contractshttp.Response {
	if err := c.service.StartProbe(ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, "Проверка сети не запустилась: "+network.ErrText(err))
	} else {
		setFlash(ctx, flashCode, "Проверка сети запущена — результат появится в таблице через несколько секунд.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

func labelUpdate(req contractshttp.ContextRequest) diag.LabelUpdate {
	all := req.All()
	field := func(name string) *string {
		if _, ok := all[name]; !ok {
			return nil
		}
		v := req.Input(name)
		return &v
	}
	return diag.LabelUpdate{Public: field("public_label"), Label: field("label"),
		Location: field("location"), Owner: field("owner"), Note: field("note")}
}

func (c *DiagnosticsController) ProbeStatus(ctx contractshttp.Context) contractshttp.Response {
	st := c.service.ProbeState()
	return ctx.Response().Json(contractshttp.StatusOK, map[string]any{"running": st.Running, "error": st.Error})
}

func (c *DiagnosticsController) Label(ctx contractshttp.Context) contractshttp.Response {
	req := ctx.Request()
	err := c.service.SetLabel(req.Input("mac"), req.Ip(), labelUpdate(req))
	if err != nil {
		setFlash(ctx, flashError, "Подпись не сохранена: "+err.Error())
	} else {
		setFlash(ctx, flashCode, "Подпись сохранена.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

func (c *DiagnosticsController) Proposal(ctx contractshttp.Context) contractshttp.Response {
	req := ctx.Request()
	ip := req.Ip()
	switch req.Input("action") {
	case "accept":
		if err := c.service.Accept(req.Input("mac"), ip); err != nil {
			setFlash(ctx, flashError, err.Error())
		} else {
			setFlash(ctx, flashCode, "Предложение принято — подпись сохранена.")
		}
	case "accept_all":
		n := c.service.AcceptAll(ip)
		setFlash(ctx, flashCode, fmt.Sprintf("Принято предложений: %d.", n))
	case "reject":
		if err := c.service.Reject(req.Input("mac"), ip); err != nil {
			setFlash(ctx, flashError, err.Error())
		} else {
			setFlash(ctx, flashCode, "Предложение отклонено.")
		}
	default:
		setFlash(ctx, flashError, "Неизвестное действие.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

func (c *DiagnosticsController) Settings(ctx contractshttp.Context) contractshttp.Response {
	st, err := diag.Edit(func(s *diag.Section) error {
		s.ActiveProbes = ctx.Request().Input("active_probes") == "1"
		s.SelfLabel = ctx.Request().Input("self_label") == "1"
		return nil
	})
	if err != nil {
		setFlash(ctx, flashError, "Не удалось сохранить настройки диагностики.")
	} else {
		c.service.Audit("diag_settings", ctx.Request().Ip(),
			"активные проверки: "+onOff(st.ActiveProbes)+", предложения подписей: "+onOff(st.SelfLabel))
		setFlash(ctx, flashCode, "Настройки диагностики сохранены.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

func windowPresets(maxHours int) []ui.Option {
	all := []ui.Option{{Value: "15", Label: "15 минут"}, {Value: "60", Label: "1 час"}, {Value: "120", Label: "2 часа"}, {Value: "240", Label: "4 часа"}, {Value: "480", Label: "8 часов"}, {Value: "1440", Label: "24 часа"}}
	var out []ui.Option
	for _, o := range all {
		if m, _ := strconv.Atoi(o.Value); m <= maxHours*60 {
			out = append(out, o)
		}
	}
	return out
}

func (c *DiagnosticsController) windowView(view map[string]any) {
	w := c.service.Window()
	st := w.State()
	view["windowOpen"] = st.Open
	view["windowFull"] = st.FullAllowed
	view["windowUntil"] = st.Until.Local().Format("02.01.2006 15:04:05")
	view["windowLeft"] = st.Remaining(time.Now()).Round(time.Minute).String()
	view["selectWindowOpen"] = ui.Select{ID: "window-open", Name: "minutes", Label: "Срок окна", Value: "120", Options: windowPresets(st.MaxHours),
		Hint: "Срок считается от открытия. Бессрочного окна не бывает: предел " + strconv.Itoa(st.MaxHours) + " ч."}
	view["toggleWindowFull"] = ui.Toggle{ID: "window-full", Name: "full", Label: "Разрешить полный замер до гигабита",
		Hint: "Полный замер занимает порт сервера целиком; без этого флажка сотрудникам доступна только быстрая проверка."}
	view["buttonWindowOpen"] = ui.Button{Label: "Открыть окно", Name: "action", Value: "open"}
	view["selectWindowExtend"] = ui.Select{ID: "window-extend", Name: "minutes", Label: "Продлить на", Value: "60", Options: windowPresets(st.MaxHours)}
	view["buttonWindowExtend"] = ui.Button{Label: "Продлить", Name: "action", Value: "extend", Kind: "secondary"}
	view["buttonWindowClose"] = ui.Button{Label: "Закрыть сейчас", Name: "action", Value: "close", Kind: "danger"}
	view["fieldWindowMax"] = ui.Field{ID: "window-max", Name: "max_hours", Type: "number", Label: "Верхний предел срока окна, часов",
		Value: strconv.Itoa(st.MaxHours), Min: "1", Max: strconv.Itoa(diag.WindowMaxHrsHi), Hint: "От 1 до 24. Открытое окно длиннее нового предела укорачивается."}
	view["buttonWindowMax"] = ui.Button{Label: "Сохранить предел", Kind: "secondary", Small: true}
}

func (c *DiagnosticsController) Window(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	if !c.window.Allow("window") {
		setFlash(ctx, flashError, "Слишком частые действия с окном проверок. Подождите минуту.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
	}
	w := c.service.Window()
	minutes, _ := strconv.Atoi(ctx.Request().Input("minutes"))
	d := time.Duration(minutes) * time.Minute
	switch ctx.Request().Input("action") {
	case "open":
		full := ctx.Request().Input("full") == "1"
		st, err := w.Open(d, full)
		if err != nil {
			setFlash(ctx, flashError, "Окно не открыто: срок от 1 минуты до "+strconv.Itoa(w.MaxHours())+" ч.")
			break
		}
		c.service.Audit("lan_window_opened", ip, "до "+st.Until.Local().Format("02.01.2006 15:04:05")+", полный замер: "+onOff(full))
		setFlash(ctx, flashCode, "Окно проверок открыто до "+st.Until.Local().Format("15:04:05")+".")
	case "extend":
		st, err := w.Extend(d)
		if err != nil {
			setFlash(ctx, flashError, "Окно не продлено: "+err.Error()+".")
			break
		}
		c.service.Audit("lan_window_extended", ip, "до "+st.Until.Local().Format("02.01.2006 15:04:05"))
		setFlash(ctx, flashCode, "Окно продлено до "+st.Until.Local().Format("15:04:05")+".")
	case "close":
		if err := w.Close(); err != nil {
			setFlash(ctx, flashError, "Окно не закрыто.")
			break
		}
		c.service.Audit("lan_window_closed", ip, "закрыто администратором")
		setFlash(ctx, flashCode, "Окно проверок закрыто.")
	case "max":
		h, err := strconv.Atoi(ctx.Request().Input("max_hours"))
		if err == nil {
			_, err = diag.Edit(func(s *diag.Section) error { s.WindowMaxHours = h; return nil })
		}
		if err != nil {
			setFlash(ctx, flashError, "Предел не сохранён: укажите от 1 до "+strconv.Itoa(diag.WindowMaxHrsHi)+" часов.")
			break
		}
		c.service.Audit("lan_window_limit", ip, "верхний предел срока: "+strconv.Itoa(h)+" ч")
		setFlash(ctx, flashCode, "Верхний предел срока окна: "+strconv.Itoa(h)+" ч.")
	default:
		setFlash(ctx, flashError, "Неизвестное действие.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

type identifyRow struct {
	MAC, IP, Segment, Hostname, Vendor, Note string
	When, FirstSeen, LastSeen, LeaseUntil    string
	RandomMAC, Online                        bool
	Count                                    int
	Label, Proposal                          string
	Location, Owner                          string
}

func (c *DiagnosticsController) identifyView(view map[string]any) {
	reqs := c.service.IdentifyRequests()
	rows := make([]identifyRow, 0, len(reqs))
	for _, d := range reqs {
		r := identifyRow{MAC: d.MAC, IP: d.IdentifyIP, Segment: d.IdentifySegment, Hostname: d.Hostname, Vendor: oui.Vendor(d.MAC),
			Note: d.IdentifyNote, When: d.IdentifyRequestedAt.Local().Format("02.01.2006 15:04:05"),
			FirstSeen: d.FirstSeenAt.Local().Format("02.01.2006 15:04:05"), LastSeen: d.LastSeenAt.Local().Format("02.01.2006 15:04:05"),
			RandomMAC: keagen.IsRandomMAC(d.MAC), Count: d.IdentifyCount, Label: diag.VisibleLabel(d),
			Proposal: joinNonEmpty(d.ProposedLabel, d.ProposedLocation, d.ProposedOwner),
			Location: d.Location, Owner: d.Owner}
		if id := c.service.Identify(d.IdentifyIP); id.Found && id.MAC == d.MAC {
			r.Online = true
			if !id.LeaseUntil.IsZero() {
				r.LeaseUntil = id.LeaseUntil.Local().Format("02.01.2006 15:04:05")
			}
		}
		rows = append(rows, r)
	}
	view["identifyRequests"] = rows
}

func (c *DiagnosticsController) IdentifyAction(ctx contractshttp.Context) contractshttp.Response {
	req := ctx.Request()
	ip, mac := req.Ip(), req.Input("mac")
	switch req.Input("action") {
	case "sign":
		if err := c.service.SetLabel(mac, ip, labelUpdate(req)); err != nil {
			setFlash(ctx, flashError, "Подпись не сохранена: "+err.Error())
			break
		}
		if err := c.service.CloseIdentify(mac, ip, "подписано администратором"); err != nil {
			setFlash(ctx, flashError, "Подпись сохранена, но запрос не закрыт: "+err.Error())
			break
		}
		setFlash(ctx, flashCode, "Компьютер подписан, запрос закрыт.")
	case "close":
		if err := c.service.CloseIdentify(mac, ip, "закрыто без подписи"); err != nil {
			setFlash(ctx, flashError, "Запрос не закрыт: "+err.Error())
			break
		}
		setFlash(ctx, flashCode, "Запрос закрыт.")
	default:
		setFlash(ctx, flashError, "Неизвестное действие.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}

func (c *DiagnosticsController) fullCheckView(view map[string]any) {
	st := c.service.FullCheck().State()
	view["fullCheck"] = st.Active
	view["fullCheckUntil"] = st.Until.Local().Format("02.01.2006 15:04:05")
	view["fullCheckLeft"] = st.Remaining(time.Now()).Round(time.Minute).String()
	if col := metrics.Current(); col != nil {
		p := col.Protection()
		view["fullLoadKnown"] = p.OK
		view["fullLoadCPU"] = fmt.Sprintf("%.0f", p.CPUBusy)
		view["fullLoadPSI"] = fmt.Sprintf("%.0f", p.PressureCPU)
		view["fullLoadLAN"] = fmt.Sprintf("%.0f", p.LANSpeed)
	}
	opts := append([]ui.Option{{Value: "", Label: "— выберите срок —", Disabled: true}}, windowPresets(c.service.Window().MaxHours())...)
	view["selectFullCheck"] = ui.Select{ID: "fullcheck-minutes", Name: "minutes", Label: "Срок полной проверки", Value: "", Options: opts,
		Hint: "Срок выбирается явно. По его истечении все пределы вернутся сами."}
	view["toggleFullConsent"] = ui.Toggle{ID: "fullcheck-consent", Name: "consent", Label: "Я понимаю: на это время сняты все пределы, качество звонков не гарантируется",
		Hint: "На слабом сервере полная проверка может упереться в процессор или порт — это тоже находка."}
	view["buttonFullStart"] = ui.Button{Label: "Начать полную проверку", Name: "action", Value: "start", Kind: "danger"}
	view["buttonFullStop"] = ui.Button{Label: "Остановить", Name: "action", Value: "stop", Kind: "danger"}
}

func (c *DiagnosticsController) FullCheckAction(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	if !c.window.Allow("fullcheck") {
		setFlash(ctx, flashError, "Слишком частые действия. Подождите минуту.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
	}
	fc := c.service.FullCheck()
	switch ctx.Request().Input("action") {
	case "start":
		minutes, _ := strconv.Atoi(ctx.Request().Input("minutes"))
		st, err := fc.Start(time.Duration(minutes)*time.Minute, ctx.Request().Input("consent") == "1", ip)
		if err != nil {
			setFlash(ctx, flashError, "Полная проверка не начата: "+err.Error()+".")
			break
		}
		setFlash(ctx, flashCode, "Полная проверка идёт до "+st.Until.Local().Format("15:04:05")+". Пределы вернутся сами.")
	case "stop":
		if err := fc.Stop(ip); err != nil {
			setFlash(ctx, flashError, "Не удалось остановить.")
			break
		}
		setFlash(ctx, flashCode, "Полная проверка остановлена, пределы возвращены.")
	default:
		setFlash(ctx, flashError, "Неизвестное действие.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/diagnostics")
}
