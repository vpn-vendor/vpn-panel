package controllers

import (
	"strconv"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

const qosJudgeOwner = "раздел QoS"

func qosHero(view map[string]any) ui.HeroStatus {
	enabled, _ := view["enabled"].(bool)
	active, _ := view["queueActive"].(bool)
	down, _ := view["downMbit"].(int)
	up, _ := view["upMbit"].(int)
	h := ui.HeroStatus{}
	switch {
	case enabled && active:
		h.Title = "Приоритет разговоров работает"
		h.Text = "Звонки идут вперёд закачек. Канал держим чуть ниже тарифа, чтобы очередь копилась на шлюзе, а не у провайдера."
		h.Judged = ui.Judge(ui.OK, qosJudgeOwner)
	case enabled:
		h.Title = "Приоритет разговоров включён, но ещё не действует"
		h.Text = "Настройки сохранены; очередь заработает, когда у шлюза будет карта в интернет."
		h.Judged = ui.Judge(ui.Warn, qosJudgeOwner)
	default:
		h.Title = "Приоритет разговоров выключен"
		h.Text = "Без очереди звонки делят канал с закачками и рвутся первыми. Включите и укажите скорость тарифа."
		h.Judged = ui.Judge(ui.Warn, qosJudgeOwner)
	}

	capText := func(v any) string {
		if n, ok := v.(int); ok && n > 0 && active {
			return strconv.Itoa(n)
		}
		return "—"
	}
	capUnit := func(v string) string {
		if v == "—" {
			return ""
		}
		return "Мбит/с"
	}
	tariff := func(n int) string {
		if n <= 0 {
			return "тариф не указан"
		}
		return "тариф " + strconv.Itoa(n) + " Мбит/с"
	}
	dc, uc := capText(view["appliedDown"]), capText(view["appliedUp"])
	h.Metrics = append(h.Metrics,
		ui.Metric{Label: "Скачивание держим до", Value: dc, Unit: capUnit(dc), Note: tariff(down)},
		ui.Metric{Label: "Отдачу держим до", Value: uc, Unit: capUnit(uc), Note: tariff(up)})

	port := ui.Metric{Label: "Порт в интернет", Value: "—", Note: "скорость карты не определена"}
	if link, ok := view["linkMbit"].(int); ok && link > 0 {
		port.Value, port.Unit, port.Note = strconv.Itoa(link), "Мбит/с", "не узкое место"
		if down > link {
			port.Note = "медленнее тарифа: очередь не поможет"
			port.Judged = ui.Judge(ui.Warn, qosJudgeOwner)
		}
	}
	h.Metrics = append(h.Metrics, port)
	return h
}

func qosSwitch(on bool) ui.SwitchRow {
	return ui.SwitchRow{ID: "qos-enabled", Name: "enabled", Checked: on, Label: "Приоритет разговоров",
		Text: "Звонки идут первыми. Настройки телефонии на сервере уже оптимизированы; здесь включается защита от перегрузки канала."}
}
