package controllers

import (
	"strconv"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

func takeoverRow(state, takeover string) *ui.WaitCheck {
	if takeover == "" {
		return nil
	}
	row := ui.WaitCheck{Key: "takeover", State: "todo", Title: "Старый шлюз выключится после подтверждения",
		Desc: "Пока идёт проверка, старое только остановлено: если сеть не подтвердится, оно вернётся"}
	switch {
	case state == network.WatchRolledBack:
		row.Title, row.Desc = "Старый шлюз снова работает", "Шлюз вернул его вместе с прежней сетью"
	case takeover == "done":
		row.State, row.Title, row.Desc = "done", "Старый шлюз выключен", "Его файлы лежат в резервной копии на сервере"
	case takeover == "partial":
		row.State, row.Title, row.Desc = "fail", "Часть старого не выключилась", "Подробности в «Диагностике»; шлюз попробует ещё раз сам"
	case state == network.WatchConfirmed:
		row.State, row.Title, row.Desc = "now", "Выключаем старый шлюз", "Старые службы выключаются, файлы уходят в резервную копию"
	}
	return &row
}

func waitView(v network.WatchView, internet bool, takeover string) ui.Wait {
	addr := ui.WaitCheck{Key: "address", Title: "Провайдер выдал адрес", Desc: "Адрес получен, связь с провайдером есть"}
	if v.Method == "static" {
		addr.Title, addr.Desc = "Адрес из договора назначен", "Маршрут в интернет идёт через провайдера"
	}
	net := ui.WaitCheck{Key: "internet", State: "todo", Title: "Интернет отвечает", Desc: "Сайты открываются"}
	w := ui.Wait{State: v.State, Left: v.Left, Checks: []ui.WaitCheck{
		{Key: "saved", State: "done", Title: "Настройки сохранены на диск", Desc: "Переживут даже обрыв питания"},
		{Key: "applied", State: "done", Title: "Сеть применена", Desc: "Шлюз поменял настройки карт"},
	}}
	switch v.State {
	case network.WatchConfirmed:
		addr.State = "done"
		net.State = "now"
		if internet {
			net.State = "done"
		}
		w.Dash, w.Big, w.Small = 100, "✓", "связь есть"
		w.Title = "Связь с провайдером есть"
		w.Lead = "Настройки закреплены. Нажмите «Далее» — осталось настроить офис и VPN."
	case network.WatchRolledBack:
		addr.State = "fail"
		addr.Title = "Провайдер не выдал адрес"
		addr.Desc = "Возможно, доступ привязан к старому роутеру по MAC-адресу — его адрес можно вписать на шаге провайдера — или нужен логин и пароль"
		if v.Method == "pppoe" {
			addr.Desc = "Проверьте логин и пароль из договора. Если они верны — доступ может быть привязан к старому роутеру по MAC-адресу"
		}
		w.Dash, w.Big, w.Small = 100, "↺", "прежние настройки"
		w.Title = "Вернули прежние настройки"
		w.Lead = "Провайдер не ответил, и шлюз сам вернул всё как было — офис не остался без сети. Проверьте способ подключения и привязку по MAC, потом попробуйте ещё раз."
		if takeover != "" {
			w.Lead = "Провайдер не ответил, и шлюз сам вернул всё как было: прежнюю сеть и старый шлюз. Проверьте способ подключения и привязку по MAC, потом попробуйте ещё раз."
		}
	default:
		addr.State = "now"
		if v.Total > 0 {
			w.Dash = v.Left * 100 / v.Total
		}
		w.Big = strconv.Itoa(v.Left/60) + ":" + pad2(v.Left%60)
		w.Small = "до автоматического отката"
		w.Title = "Применяем настройки сети"
		w.Lead = "Шлюз сам проверяет связь с провайдером. Если адрес не придёт за " + minutes(v.Total) +
			", шлюз вернёт прежние настройки — сломать ничего нельзя."
	}
	if row := takeoverRow(v.State, takeover); row != nil {
		w.Checks = append(w.Checks, *row)
	}
	w.Checks = append(w.Checks, addr, net)
	return w
}

func takeoverFor(f setup.Facts) string {
	if st, err := system.New().TakeoverState(); err == nil && st.State != "" && st.State != "none" {
		return st.State
	}
	if c := f.Takeover.Consent; c != nil && len(c.IDs) > 0 {
		return "consent"
	}
	return ""
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func minutes(sec int) string {
	if sec%60 == 0 {
		m := sec / 60
		return ui.Plural(m, "минуту", "минуты", "минут")
	}
	return ui.Plural(sec, "секунду", "секунды", "секунд")
}

func internetAnswers() bool {
	pm := bootstrapPathMonitor()
	if pm == nil {
		return false
	}
	for _, p := range pm.Paths() {
		if p.Kind == pathmon.Direct && p.State == pathprobe.Up {
			return true
		}
	}
	return false
}

func (c *SetupController) Applying(ctx contractshttp.Context) contractshttp.Response {
	v := network.WizardWatch()
	if v.State == network.WatchIdle {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	f := c.facts()
	step, _ := wizard.ByKey("provider")
	plan := wizard.Plan(f.Wizard())
	w := waitView(v, internetAnswers(), takeoverFor(f))
	step.Question, step.Hint = w.Title, w.Lead
	view := map[string]any{
		"error":     takeFlash(ctx, flashError),
		"ok":        takeFlash(ctx, flashCode),
		"agentDown": f.AgentDown,
		"step":      step,
		"stepper":   stepperOf(plan.Viewing("provider")),
		"back":      "",
	}
	c.fill(ctx, "applying", f, view)
	view["wait"] = w
	view["islandScript"] = "applying.js"
	foot := view["foot"].(ui.WizardFoot)
	switch v.State {
	case network.WatchConfirmed:
		foot.Primary = ui.WizardAction{Label: "Далее", URL: "/setup"}
	case network.WatchRolledBack:
		foot.Back = "/setup/provider"
		foot.Primary = ui.WizardAction{Label: "Попробовать снова", URL: "/setup/provider"}
	default:
		foot.Primary = ui.WizardAction{Label: "Оставить настройки всё равно", Form: "keep-form"}
	}
	view["foot"] = foot
	return ctx.Response().View().Make("setup/applying", page(ctx, "Первая настройка: проверка связи", "", view))
}

func (c *SetupController) ApplyingStatus(ctx contractshttp.Context) contractshttp.Response {
	f := setup.Facts{Takeover: setup.TakeoverFacts{Consent: setup.TakeoverConsent()}}
	return ctx.Response().Json(contractshttp.StatusOK, waitView(network.WizardWatch(), internetAnswers(), takeoverFor(f)))
}

func (c *SetupController) ApplyingKeep(ctx contractshttp.Context) contractshttp.Response {
	if !network.KeepWizardChange() {
		setFlash(ctx, flashError, "Настройки не закрепились — шлюз вернул прежние.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/applying")
}
