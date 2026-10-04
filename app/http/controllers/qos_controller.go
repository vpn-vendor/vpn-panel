package controllers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"

	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
)

const qosWeakCPUMbit = 500

type QosController struct {
	service *qossvc.Service
}

func NewQosController() *QosController {
	return &QosController{service: qossvc.New()}
}

func (c *QosController) Index(ctx contractshttp.Context) contractshttp.Response {
	plan := c.service.BuildPlan()
	view := map[string]any{
		"error":    takeFlash(ctx, flashError),
		"ok":       takeFlash(ctx, flashCode),
		"enabled":  plan.Enabled,
		"downMbit": plan.DownKbit / 1000,
		"upMbit":   plan.UpKbit / 1000,

		"fieldEnabled": ui.Toggle{
			ID: "qos-enabled", Name: "enabled", Checked: plan.Enabled,
			Label: "Включить приоритет разговоров",
		},
		"fieldDown": ui.Field{
			ID: "qos-down", Name: "down_mbit", Type: "number",
			Label: "Скорость тарифа на скачивание, Мбит/с",
			Value: mbitValue(plan.DownKbit), Placeholder: "например, 100",
			Min: "1", Max: "10000",
			Hint: "Цифра из договора или из замера ниже",
		},
		"fieldUp": ui.Field{
			ID: "qos-up", Name: "up_mbit", Type: "number",
			Label: "Скорость тарифа на отдачу, Мбит/с",
			Value: mbitValue(plan.UpKbit), Placeholder: "например, 50",
			Min: "1", Max: "10000",
			Hint: "Почти всегда ниже скачивания — без замера легко ошибиться",
		},
		"buttonApply": ui.Button{Label: "Применить"},
	}
	addSpeedtestView(view, c.service.Speedtest())
	view["speedBack"] = "/qos"
	var notices []notice

	if plan.WAN == "" {
		notices = append(notices, notice{Level: "warn",
			Text: "Интернет ещё не настроен: назначьте карте роль «интернет» на странице «Сеть». Сохранённые здесь настройки включатся после этого сами."})
	}
	if !plan.Enabled {

		notices = append(notices, notice{Level: "info",
			Text: "Рекомендуем включить приоритет разговоров: он защищает звонки от больших закачек. Нажмите «Запустить замер», затем «Подставить в поля тарифа» и «Применить»."})
	}

	st, err := c.service.Status()
	switch {
	case err != nil:
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			notices = append(notices, notice{Level: "error",
				Text: "Системная служба недоступна — состояние приоритета трафика получить не удалось."})
		} else {
			notices = append(notices, notice{Level: "error", Text: network.ErrText(err)})
		}
	default:

		view["queueActive"] = st.Active
		view["cores"] = st.Cores
		view["load1"] = st.Load1
		if st.LinkMbit > 0 {
			view["linkMbit"] = st.LinkMbit
		}
		if st.Active {
			view["appliedDown"] = plan.ShapedDownKbit() / 1000
			view["appliedUp"] = plan.ShapedUpKbit() / 1000
		}
		if plan.Enabled && plan.WAN != "" && !st.Active && !devmode.Enabled {
			notices = append(notices, notice{Level: "error",
				Text: "QoS включён в настройках, но очередь сейчас не работает. Нажмите «Применить» ещё раз; если не поможет — обратитесь в поддержку."})
		}

		if plan.Enabled && st.LinkMbit > 0 && plan.DownKbit/1000 > st.LinkMbit {
			text := fmt.Sprintf("Указанная скорость тарифа (%d Мбит/с) выше скорости сетевой карты (%d Мбит/с) — приоритет работать не будет.",
				plan.DownKbit/1000, st.LinkMbit)
			if st.LinkMbit == 100 {

				text += " Частая причина: кабель от провайдера 4-жильный, он даёт максимум 100 Мбит/с — попросите заменить на 8-жильный."
			} else {
				text += " Укажите скорость из договора с провайдером или запустите замер."
			}
			notices = append(notices, notice{Level: "warn", Text: text})
		}
		if plan.Enabled && st.Cores <= 2 && plan.DownKbit/1000 >= qosWeakCPUMbit {
			notices = append(notices, notice{Level: "warn",
				Text: "Возможностей процессора этого сервера может не хватить для выбранной скорости: при больших закачках звонки могут пострадать. Рекомендуем тариф до 500 Мбит/с или более мощный сервер."})
		}
	}

	view["notices"] = notices
	return ctx.Response().View().Make("qos.tmpl", page(ctx, "QoS", "qos", view))
}

var errTariffNumber = errors.New("скорость тарифа не числом")

const tariffNumberText = "Укажите скорость тарифа числом в Мбит/с: лучший источник — кнопка «Запустить замер» ниже, запасной — договор с провайдером."

func tariffFromForm(ctx contractshttp.Context, s *qossvc.Section, enabled bool) error {
	for _, f := range []struct {
		name string
		dst  *int
	}{{"down_mbit", &s.DownKbit}, {"up_mbit", &s.UpKbit}} {
		raw := strings.TrimSpace(ctx.Request().Input(f.name))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		switch {
		case err == nil:
			*f.dst = n * 1000
		case enabled:
			return errTariffNumber
		}
	}
	return nil
}

func (c *QosController) Apply(ctx contractshttp.Context) contractshttp.Response {
	enabled := ctx.Request().Input("enabled") == "1"
	if _, err := qossvc.Edit(func(s *qossvc.Section) error {
		s.Enabled = enabled
		return tariffFromForm(ctx, s, enabled)
	}); err != nil {
		text := err.Error()
		if errors.Is(err, errTariffNumber) {
			text = tariffNumberText
		}
		setFlash(ctx, flashError, text)
		return ctx.Response().Redirect(contractshttp.StatusFound, "/qos")
	}

	plan := c.service.BuildPlan()
	if enabled && plan.WAN == "" {

		setFlash(ctx, flashCode, "Настройки сохранены. Приоритет включится автоматически, как только на странице «Сеть» будет назначена роль «интернет».")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/qos")
	}

	res, err := c.service.Apply(plan)
	if err != nil {
		setFlash(ctx, flashError, "Настройки сохранены, но применить их не удалось: "+network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/qos")
	}
	switch {
	case !enabled:
		setFlash(ctx, flashCode, "QoS выключен — очередь возвращена к стандартной.")
	case res.Changed:
		setFlash(ctx, flashCode, fmt.Sprintf(
			"QoS включён: скорость ограничена %d/%d Мбит/с (немного ниже тарифа — так звонки остаются чистыми даже при полной загрузке канала).",
			res.DownKbit/1000, res.UpKbit/1000))
	default:
		setFlash(ctx, flashCode, "Изменений нет — приоритет разговоров уже работает с этими настройками.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/qos")
}

func (c *QosController) Speedtest(ctx contractshttp.Context) contractshttp.Response {
	back := "/qos"

	if ctx.Request().Input("back") == "/setup/speed" {
		back = "/setup/speed"
	}
	if err := c.service.StartSpeedtest(); err != nil {
		setFlash(ctx, flashError, err.Error())
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, back)
}

func (c *QosController) SpeedtestStatus(ctx contractshttp.Context) contractshttp.Response {
	st := c.service.Speedtest()
	return ctx.Response().Json(contractshttp.StatusOK, map[string]any{
		"running": st.Running,
	})
}

type measureRow struct {
	Name  string
	Speed string
}

func addSpeedtestView(view map[string]any, st qossvc.SpeedtestState) {
	view["measuring"] = st.Running

	view["measureDev"] = devmode.Enabled
	if st.Error != "" {
		view["measureError"] = st.Error
	}
	if st.Result == nil {
		return
	}
	rows := make([]measureRow, 0, len(st.Result.Down))
	for _, r := range st.Result.Down {
		rows = append(rows, measureRow{Name: r.Name, Speed: speedText(r.Kbit)})
	}
	upRows := make([]measureRow, 0, len(st.Result.Up))
	for _, r := range st.Result.Up {
		upRows = append(upRows, measureRow{Name: r.Name, Speed: speedText(r.Kbit)})
	}
	view["measureDownRows"] = rows
	view["measureUpRows"] = upRows
	view["measureDownMbit"] = st.Result.DownKbit / 1000
	view["measureUpMbit"] = st.Result.UpKbit / 1000
	view["measureDivergent"] = st.Result.Divergent
}

func speedText(kbit int) string {
	if kbit <= 0 {
		return "недоступен"
	}
	return fmt.Sprintf("%d Мбит/с", kbit/1000)
}

func mbitValue(kbit int) string {
	if kbit <= 0 {
		return ""
	}
	return strconv.Itoa(kbit / 1000)
}
