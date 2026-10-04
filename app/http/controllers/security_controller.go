package controllers

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/disk"
	"github.com/vpn-vendor/vpn-panel-core/app/services/listen"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overload"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/bindset"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type SecurityController struct {
	orch     *network.Orchestrator
	network  *network.Service
	security *security.Service
	updates  *updates.Service
	disk     *disk.Service

	switches *ratelimit.Limiter
}

func NewSecurityController() *SecurityController {
	orch := network.NewOrchestrator()
	switches := ratelimit.New(6, 1, time.Minute)
	return &SecurityController{orch: orch, network: orch.Network(),
		security: security.New(), updates: updates.New(), disk: disk.New(), switches: switches}
}

type listenerView struct {
	URL   string
	Iface string
}

func (c *SecurityController) Index(ctx contractshttp.Context) contractshttp.Response {
	settings := c.security.Load()
	view := map[string]any{
		"error":      takeFlash(ctx, flashError),
		"ok":         takeFlash(ctx, flashCode),
		"hiddenMode": settings.HiddenMode,
		"ipv6":       settings.IPv6,
		"rolesReady": c.network.HasWANAndLAN(),
		"agentDown":  false,
		"protected":  false,
	}
	var notices []notice

	st, err := c.security.Status()
	switch {
	case devmode.Enabled:

	case err == nil:
		view["protected"] = st.InputFiltered
		view["pingAnswered"] = st.PingAnswered
		view["ipv6Closed"] = st.IPv6Closed
		if !st.InputFiltered {
			if c.network.HasWANAndLAN() {
				notices = append(notices, notice{Level: "error",
					Text: "Защита от подключений из интернета сейчас не действует. Нажмите «Применить» на этой странице; если не помогло — примените настройки на странице «Сеть»."})
			} else {
				notices = append(notices, notice{Level: "info",
					Text: "Защита включится вместе с ролями сетевых карт: назначьте на странице «Сеть», какая карта смотрит в интернет, а какая — в офис."})
			}
		}
	default:
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			view["agentDown"] = true
		} else {
			notices = append(notices, notice{Level: "warn",
				Text: "Не удалось прочитать состояние защиты. Обновите страницу; если повторяется — обратитесь в поддержку."})
		}
	}

	if m := listen.Current(); m != nil {
		snap := m.Snapshot()
		port := ""
		if p := facadesTLSPort(); p != "443" && p != "" {
			port = ":" + p
		}
		rows := make([]listenerView, 0, len(snap.Addrs))
		for _, a := range snap.Addrs {
			if a.IP == bindset.Loopback {
				continue
			}
			rows = append(rows, listenerView{URL: "https://" + a.IP + port, Iface: a.Iface})
		}
		view["listeners"] = rows
		view["listenMode"] = string(snap.Mode)
		if snap.Mode == bindset.ModePreRoles {
			notices = append(notices, notice{Level: "info",
				Text: "Пока роли сетевых карт не назначены, панель открыта по всем локальным (частным) адресам сервера — так к ней можно подключиться с любого компьютера офиса. После назначения ролей она останется только в локальной сети."})
		}
	}

	if !settings.IPv6 {
		if nst, err := c.network.Status(); err == nil {
			roles := c.network.Roles()
			for _, i := range nst.Interfaces {
				r, ok := roles[i.Name]
				if !ok || (r.Role != "wan" && r.Role != "lan") {
					continue
				}
				for _, cidr := range i.Addresses {
					if ip, _, err := net.ParseCIDR(cidr); err == nil && ip.To4() == nil {
						notices = append(notices, notice{Level: "warn",
							Text: "У карты «" + i.Name + "» есть адрес IPv6, хотя IPv6 выключен. Нажмите «Применить», чтобы убрать его; если он появляется снова — обратитесь в поддержку."})
						break
					}
				}
			}
		}
	}

	if ust, err := c.updates.Status(); err == nil {
		view["autoUpdates"] = ust.Enabled
		view["updatesKnown"] = true
		view["updatesTool"] = ust.ToolPresent
		view["panelVersion"] = ust.Version
		view["updatesLastRun"] = lastRunText(ust.LastRun)
		if ust.Enabled && !ust.TimerActive {
			notices = append(notices, notice{Level: "warn",
				Text: "Автоматические обновления включены, но системный таймер обновлений не запущен — обновления не придут. Выключите и включите ручку заново; если повторится, обратитесь в поддержку."})
		}
	}

	if dst, err := c.disk.Status(); err == nil && !devmode.Enabled {
		view["diskKnown"] = true
		view["diskEncrypted"] = dst.Encrypted
		view["diskPending"] = dst.FirstBootPending
		view["diskCipher"] = disk.CipherText(*dst)
		view["diskTrim"] = dst.Discards
		view["diskManySlots"] = dst.Slots > 1
		view["diskChangeRequested"] = dst.ChangeRequested
		view["diskKeymapDrift"] = dst.UnlockKeymap == "system"
		last, warn := disk.LastChangeText(*dst)
		view["diskLast"], view["diskLastWarn"] = last, warn
	}

	keep := retention.Load()
	view["fieldJournalDays"] = ui.Field{
		ID: "retention-journal", Name: "journal_days", Type: "number",
		Label: "Сколько дней хранить журнал безопасности",
		Value: strconv.Itoa(keep.JournalDays),
		Min:   strconv.Itoa(retention.JournalDaysMin), Max: strconv.Itoa(retention.JournalDaysMax),
		Hint: fmt.Sprintf("От %d до %d дней. Выдача кодов, подключение устройств и смена настроек хранятся в пределах этого срока всегда, даже если кто-то в сети засыпает журнал попытками.", retention.JournalDaysMin, retention.JournalDaysMax),
	}
	view["fieldForgetDays"] = ui.Field{
		ID: "retention-forget", Name: "forget_days", Type: "number",
		Label: "Через сколько дней забывать неподписанные устройства со случайным MAC",
		Value: strconv.Itoa(keep.ForgetDays),
		Min:   strconv.Itoa(retention.ForgetDaysMin), Max: strconv.Itoa(retention.ForgetDaysMax),
		Hint: fmt.Sprintf("От %d до %d дней. Телефоны и ноутбуки меняют случайный адрес, и без забывания список устройств растёт годами. Подписанные устройства не забываются никогда.", retention.ForgetDaysMin, retention.ForgetDaysMax),
	}
	view["fieldTrustDays"] = ui.Field{
		ID: "retention-trust", Name: "trust_days", Type: "number",
		Label: "Сколько дней помнить устройства, которые вышли из панели",
		Value: strconv.Itoa(keep.TrustDays),
		Min:   strconv.Itoa(retention.TrustKeepDaysMin), Max: strconv.Itoa(retention.TrustKeepDaysMax),
		Hint: fmt.Sprintf("От %d до %d дней. Устройство, которое вышло, было отозвано или долго не входило, в панель уже не пускается; запись о нём хранится для журнала, потом удаляется.", retention.TrustKeepDaysMin, retention.TrustKeepDaysMax),
	}
	view["buttonRetention"] = ui.Button{Label: "Сохранить сроки", Kind: "secondary"}

	disk := retention.CurrentDisk()
	view["diskKnown"] = !disk.Checked.IsZero() && disk.Error == ""
	view["diskAvail"] = retention.Human(disk.AvailUnpriv)
	view["diskTotal"] = retention.Human(disk.Total)
	view["diskOurs"] = retention.Human(disk.Ours)
	view["diskBudget"] = retention.Human(disk.Budget)
	view["diskCeiling"] = retention.Human(disk.Ceiling)
	view["diskStarved"] = disk.Starved
	view["diskOverBudget"] = disk.OverBudget()
	view["diskPressure"] = disk.Pressure
	view["logsTotal"] = retention.Human(disk.LogsTotal())
	view["logsEmpty"] = disk.LogsTotal() < 8*retention.MiB
	if !disk.LastTrim.IsZero() {
		view["logsLastTrim"] = disk.LastTrim.Local().Format("02.01.2006 15:04:05")
	}
	logRows := make([]map[string]string, 0, len(disk.Logs))
	for _, f := range disk.Logs {
		logRows = append(logRows, map[string]string{"Name": f.Name, "Live": retention.Human(f.Live), "Rotated": retention.Human(f.Rotated)})
	}
	view["logRows"] = logRows
	budgetMB := int(disk.Budget / retention.MiB) //nolint:gosec
	if disk.AdminBudget > 0 {
		budgetMB = int(disk.AdminBudget / retention.MiB) //nolint:gosec
	}
	view["fieldDiskBudget"] = ui.Field{
		ID: "disk-budget", Name: "budget_mb", Type: "number",
		Label: "Бюджет диска для данных панели, МБ",
		Value: strconv.Itoa(budgetMB),
		Min:   strconv.Itoa(retention.BudgetFloor / retention.MiB), Max: strconv.FormatUint(disk.Ceiling/retention.MiB, 10),
		Hint: fmt.Sprintf("По умолчанию 2048 МБ. Сейчас можно до %s — потолок считается от свободного места и меняется сам; выше него панель не даст поставить. Данные панели занимают %s.", retention.Human(disk.Ceiling), retention.Human(disk.Ours)),
	}
	view["buttonDiskBudget"] = ui.Button{Label: "Сохранить бюджет", Kind: "secondary"}
	view["toggleSyslogCap"] = ui.Toggle{
		ID: "syslog-cap", Name: "syslog_cap", Checked: disk.SyslogCap,
		Label: "Ограничить системные журналы: не больше " + retention.Human(retention.SyslogCap) + " на файл",
		Hint:  "Системные журналы сервера (не панели) по умолчанию ничем не ограничены и при неисправности могут заполнить диск за минуты. С этим выключателем панель каждые 10 секунд обрезает разросшийся файл, сохраняя его хвост.",
	}
	view["buttonSyslogCap"] = ui.Button{Label: "Применить", Kind: "secondary"}
	view["buttonLogsTrim"] = ui.Button{Label: "Очистить системные журналы сейчас", Kind: "danger", Disabled: disk.LogsTotal() < 8*retention.MiB}

	if col := metrics.Current(); col != nil {
		snap := col.View()
		view["metricsKnown"] = true
		view["metricsMaster"] = describeState(snap.Master)
		view["metricsMasterOff"] = snap.Master.Mode == metrics.Off
		view["selectMetricsMaster"] = ui.Select{ID: "metrics-master", Name: "mode", Label: "Главный рубильник сбора",
			Value: modeValue(snap.Master), Options: modeOptions(),
			Hint: "«Выключен насовсем» выбирается явно и даёт уведомление на всех страницах. Пауза возвращается сама по сроку."}
		view["fieldMetricsPause"] = ui.Field{ID: "metrics-pause", Name: "pause_minutes", Type: "number", Label: "Срок паузы, минут",
			Value: "60", Min: "1", Max: "1440", Hint: "Действует для состояния «пауза до времени»."}
		view["buttonMetricsMaster"] = ui.Button{Label: "Применить к сбору", Kind: "secondary"}
		var rows []map[string]any
		for _, src := range snap.Sources {
			rows = append(rows, map[string]any{
				"Name": src.Name, "Title": src.Title, "Depends": src.Depends,
				"Own": describeState(src.Own), "Effective": describeState(src.Effective),
				"Cost": src.Cost.Round(time.Microsecond).String(),
				"Select": ui.Select{ID: "metrics-src-" + strings.ReplaceAll(src.Name, ".", "-"), Name: "mode", Label: "Состояние",
					Value: modeValue(src.Own), Options: modeOptions()},
				"Button": ui.Button{Label: "Сохранить", Kind: "secondary", Small: true},
			})
		}
		view["metricsSources"] = rows
		view["metricsProtectOK"] = snap.Protect.OK
		view["metricsProtectCPU"] = fmt.Sprintf("%.0f", snap.Protect.CPUBusy)
		view["metricsProtectPSI"] = fmt.Sprintf("%.0f", snap.Protect.PressureCPU)
		view["metricsProtectLAN"] = fmt.Sprintf("%.0f", snap.Protect.LANSpeed)
	}

	if g := overload.Current(); g != nil {
		snap := g.Snapshot()
		view["gateKnown"] = true
		view["gateOverloaded"] = snap.Overloaded
		view["gateWhy"] = "очередь запросов: ожидание выше цели"
		if snap.SignalHot {
			view["gateWhy"] = snap.SignalName + " — " + snap.SignalWhy
		}
		view["gateInflight"] = snap.Inflight
		view["gateWaiting"] = snap.Waiting
		view["gateEpisodes"] = snap.Episodes
		view["gateShed"] = snap.Shed[0] + snap.Shed[1] + snap.Shed[2]
		view["gateShedCritical"] = snap.Shed[2]
		if !snap.Since.IsZero() {
			view["gateSince"] = snap.Since.Local().Format("02.01.2006 15:04:05")
		}
	}

	view["notices"] = notices
	return ctx.Response().View().Make("security.tmpl", page(ctx, "Защита", "security", view))
}

func (c *SecurityController) DiskBudget(ctx contractshttp.Context) contractshttp.Response {
	mb, err := strconv.Atoi(ctx.Request().Input("budget_mb"))
	if err != nil {
		setFlash(ctx, flashError, "Бюджет не сохранён: укажите целое число мегабайт.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}

	if err := retention.SaveDiskBudget(mb); err != nil {
		setFlash(ctx, flashError, "Бюджет не сохранён: "+err.Error()+".")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	c.network.Audit("disk_budget", ctx.Request().Ip(), fmt.Sprintf("бюджет диска панели: %d МБ", mb))
	setFlash(ctx, flashCode, "Бюджет диска сохранён.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) SyslogCap(ctx contractshttp.Context) contractshttp.Response {
	on := ctx.Request().Input("syslog_cap") == "1"
	if _, err := retention.Edit(func(s *retention.Section) error { s.SyslogCap = on; return nil }); err != nil {
		setFlash(ctx, flashError, "Настройку сохранить не удалось.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	c.network.Audit("syslog_cap", ctx.Request().Ip(), "ограничение системных журналов: "+onOff(on))
	if on {
		setFlash(ctx, flashCode, "Ограничение включено: разросшийся системный журнал будет обрезаться до "+retention.Human(retention.SyslogCap)+" с сохранением хвоста.")
	} else {
		setFlash(ctx, flashCode, "Ограничение выключено. Сторож диска по-прежнему обрежет журналы, если место на диске почти кончится.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) LogsTrim(ctx contractshttp.Context) contractshttp.Response {
	res, err := retention.TrimSyslog(nil)
	if err != nil {
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			setFlash(ctx, flashError, "Системная служба недоступна — журналы не очищены.")
		} else {
			setFlash(ctx, flashError, network.ErrText(err))
		}
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	c.network.Audit("syslog_trimmed", ctx.Request().Ip(), "по кнопке администратора, освобождено "+retention.Human(res.Freed))
	setFlash(ctx, flashCode, "Системные журналы очищены, освобождено "+retention.Human(res.Freed)+". Последние записи каждого журнала сохранены.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) Retention(ctx contractshttp.Context) contractshttp.Response {
	journal, err1 := strconv.Atoi(ctx.Request().Input("journal_days"))
	forget, err2 := strconv.Atoi(ctx.Request().Input("forget_days"))
	trust, err3 := strconv.Atoi(ctx.Request().Input("trust_days"))
	if err1 != nil || err2 != nil || err3 != nil {
		setFlash(ctx, flashError, "Сроки не сохранены: укажите целое число дней.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}

	if _, err := retention.Edit(func(s *retention.Section) error {
		s.JournalDays, s.ForgetDays, s.TrustDays = journal, forget, trust
		return nil
	}); err != nil {
		setFlash(ctx, flashError, "Сроки не сохранены: "+err.Error()+".")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	c.network.Audit("retention_settings", ctx.Request().Ip(),
		fmt.Sprintf("журнал: %d дн., забывание устройств: %d дн., вышедшие устройства входа: %d дн.", journal, forget, trust))
	setFlash(ctx, flashCode, "Сроки хранения сохранены. Уборка применит их в течение минуты.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) Apply(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	var editErr error
	edit := func() error {
		var settings security.Section
		settings, editErr = security.Edit(func(s *security.Section) error {
			s.HiddenMode = ctx.Request().Input("hidden_mode") == "1"
			s.IPv6 = ctx.Request().Input("ipv6") == "1"
			return nil
		})
		if editErr == nil {
			c.network.Audit("security_settings", ip,
				"скрытый режим: "+onOff(settings.HiddenMode)+", IPv6: "+onOff(settings.IPv6))
		}
		return editErr
	}
	saveFailed := func() contractshttp.Response {
		setFlash(ctx, flashError, "Не удалось сохранить настройки защиты: "+editErr.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}

	if !c.network.HasWANAndLAN() {

		if edit() != nil {
			return saveFailed()
		}
		setFlash(ctx, flashCode, "Настройки сохранены. Они вступят в силу вместе с ролями сетевых карт — назначьте их на странице «Сеть».")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	st, err := c.network.Status()
	if err != nil {
		setFlash(ctx, flashError, "Системная служба недоступна — применить нельзя.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}

	outcome, err := c.orch.Change(ip, st, network.ApplySecrets{}, edit)
	if editErr != nil {
		return saveFailed()
	}
	if err != nil {
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	if outcome.AwaitingConfirm {
		setFlash(ctx, flashReturn, "/security")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network/confirming")
	}
	setFlash(ctx, flashCode, "Настройки защиты применены. "+outcome.Message)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) Updates(ctx contractshttp.Context) contractshttp.Response {
	on := ctx.Request().Input("auto_updates") == "1"
	st, err := c.updates.Set(on)
	if err != nil {
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			setFlash(ctx, flashError, "Системная служба недоступна — настройку обновлений сохранить не удалось.")
		} else {
			setFlash(ctx, flashError, network.ErrText(err))
		}
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	c.network.Audit("auto_updates", ctx.Request().Ip(), "автообновления: "+onOff(st.Enabled))
	if st.Enabled {
		setFlash(ctx, flashCode, "Автоматические обновления включены. Панель будет обновляться сама, обновляется только она — системные пакеты не трогаются.")
	} else {
		setFlash(ctx, flashCode, "Автоматические обновления выключены. Обновлять панель нужно вручную.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) DiskChange(ctx contractshttp.Context) contractshttp.Response {
	on := ctx.Request().Input("requested") == "1"
	if _, err := c.disk.RequestChange(on); err != nil {
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			setFlash(ctx, flashError, "Системная служба недоступна — запрос смены пароля не сохранён.")
		} else {
			setFlash(ctx, flashError, network.ErrText(err))
		}
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	if on {
		c.network.Audit("disk_change", ctx.Request().Ip(), "запрошена смена пароля диска при следующем включении")
		setFlash(ctx, flashCode, "При следующем включении сервер спросит на своём экране текущий пароль диска и новый. Панель пароль не видит.")
	} else {
		c.network.Audit("disk_change", ctx.Request().Ip(), "смена пароля диска отменена")
		setFlash(ctx, flashCode, "Смена пароля диска отменена.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func lastRunText(stamp string) string {
	if stamp == "" {
		return ""
	}
	ts, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return ""
	}
	return ts.Local().Format("02.01.2006 15:04")
}

func onOff(b bool) string {
	if b {
		return "включён"
	}
	return "выключен"
}

func facadesTLSPort() string {
	p := configString("http.external_tls_port")
	if p == "" {
		p = configString("http.tls.port")
	}
	if _, err := strconv.Atoi(p); err != nil {
		return ""
	}
	return p
}

func modeOptions() []ui.Option {
	return []ui.Option{
		{Value: "on", Label: "Включён"},
		{Value: "pause", Label: "Пауза до времени"},
		{Value: "memory", Label: "Только в памяти (на диск не писать)"},
		{Value: "off", Label: "Выключен насовсем"},
	}
}

func modeValue(st metrics.State) string {
	switch st.Mode {
	case metrics.Paused:
		return "pause"
	case metrics.Memory:
		return "memory"
	case metrics.Off:
		return "off"
	}
	return "on"
}

func describeState(st metrics.State) string {
	if st.Mode == metrics.Paused {
		return "пауза до " + st.Until.Local().Format("02.01.2006 15:04")
	}
	return st.Mode.String()
}

func stateFromForm(ctx contractshttp.Context) (metrics.State, bool) {
	switch ctx.Request().Input("mode") {
	case "on":
		return metrics.State{Mode: metrics.On}, true
	case "memory":
		return metrics.State{Mode: metrics.Memory}, true
	case "off":
		return metrics.State{Mode: metrics.Off}, true
	case "pause":
		minutes, err := strconv.Atoi(ctx.Request().Input("pause_minutes"))
		if err != nil || minutes < 1 || minutes > 1440 {
			return metrics.State{}, false
		}
		return metrics.State{Mode: metrics.Paused, Until: time.Now().Add(time.Duration(minutes) * time.Minute)}, true
	}
	return metrics.State{}, false
}

func setMetrics(col *metrics.Collector, source string, st metrics.State, ip string) error {
	if st.Mode == metrics.Paused {
		if source == "" {
			return col.SetMaster(st, ip)
		}
		return col.SetSource(source, st, ip)
	}
	_, err := metrics.Edit(ip, func(s *metrics.Section) error {
		if source == "" {
			s.Master = st.String()
		} else {
			s.Sources[source] = st.String()
		}
		return nil
	})
	return err
}

func (c *SecurityController) MetricsMaster(ctx contractshttp.Context) contractshttp.Response {
	col := metrics.Current()
	if col == nil {
		setFlash(ctx, flashError, "Сбор показателей ещё не запущен.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	if !c.switches.Allow("metrics") {
		setFlash(ctx, flashError, "Слишком частые переключения сбора. Подождите минуту.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	st, ok := stateFromForm(ctx)
	if !ok {
		setFlash(ctx, flashError, "Состояние не сохранено: выберите режим, для паузы укажите срок от 1 до 1440 минут.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	if err := setMetrics(col, "", st, ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, "Не удалось сохранить состояние сбора.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	setFlash(ctx, flashCode, "Сбор показателей: "+describeState(st)+".")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}

func (c *SecurityController) MetricsSource(ctx contractshttp.Context) contractshttp.Response {
	col := metrics.Current()
	if col == nil {
		setFlash(ctx, flashError, "Сбор показателей ещё не запущен.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	if !c.switches.Allow("metrics") {
		setFlash(ctx, flashError, "Слишком частые переключения сбора. Подождите минуту.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	st, ok := stateFromForm(ctx)
	if !ok {
		setFlash(ctx, flashError, "Состояние не сохранено: выберите режим, для паузы укажите срок от 1 до 1440 минут.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	name := ctx.Request().Input("source")
	if err := setMetrics(col, name, st, ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, "Источник не найден или состояние не сохранено.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
	}
	setFlash(ctx, flashCode, "Источник показателей: "+describeState(st)+".")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/security")
}
