package controllers

import (
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

const securityJudgeOwner = "раздел «Защита»"

func securityTag(text string, level ui.Level) ui.Tag {
	return ui.Tag{Text: text, Judged: ui.Judge(level, securityJudgeOwner)}
}

func securityHero(view map[string]any) ui.HeroStatus {
	is := func(key string) bool { b, _ := view[key].(bool); return b }
	str := func(key string) string { s, _ := view[key].(string); return s }
	n := func(key string) int {
		switch v := view[key].(type) {
		case int:
			return v
		}
		return 0
	}

	var tags []ui.Tag
	ok := 0
	add := func(text string, level ui.Level) {
		tags = append(tags, securityTag(text, level))
		if level == ui.OK {
			ok++
		}
	}

	if is("exposureKnown") {
		if is("protected") {
			add("невидим из интернета", ui.OK)
		} else {
			add("виден из интернета", ui.Bad)
		}
	}
	if is("updatesKnown") {
		switch {
		case is("updatesPaused"):
			add("обновления на паузе по политике", ui.Warn)
		case is("autoUpdates"):
			add("обновляется сам", ui.OK)
		default:
			add("обновления вручную", ui.Warn)
		}
	}
	if is("releaseKnown") {
		switch str("releasePhase") {
		case "observing", "await":
			add("идёт проверка новой версии", ui.Warn)
		case "rollback_pending", "rolled_back":
			add("возврат на прежнюю версию", ui.Warn)
		case "limp":
			add("панель ждёт ручной проверки", ui.Bad)
		}
	}
	if is("encKnown") {
		switch {
		case !is("diskEncrypted"):
			add("диск не зашифрован", ui.Bad)
		case is("diskPending"):
			add("пароль диска ещё не задан", ui.Warn)
		case is("diskKeymapDrift"):
			add("раскладка экрана пароля сбита", ui.Warn)
		default:
			add("диск зашифрован", ui.OK)
		}
	}
	if is("diskKnown") {
		switch {
		case n("diskPressure") >= 2:
			add("место почти кончилось", ui.Bad)
		case n("diskPressure") == 1:
			add("места мало", ui.Warn)
		case is("diskStarved"):
			add("диск слишком мал", ui.Warn)
		default:
			add("места достаточно", ui.OK)
		}
	}
	if is("gateKnown") {
		if is("gateOverloaded") {
			add("панель перегружена", ui.Warn)
		} else {
			add("нагрузка обычная", ui.OK)
		}
	}
	if is("policyKnown") {
		if is("policyAllClear") {
			add("ограничений политики нет", ui.OK)
		} else {
			add("действует ограничение политики", ui.Warn)
		}
	}
	if is("metricsKnown") && is("metricsMasterOff") {
		add("сбор показателей выключен", ui.Warn)
	}

	h := ui.HeroStatus{Tags: tags}
	worst := ui.None
	var good, notes []string
	for _, t := range tags {
		switch t.Judged.Level() {
		case ui.Bad:
			worst = ui.Bad
			notes = append(notes, t.Text)
		case ui.Warn:
			if worst != ui.Bad {
				worst = ui.Warn
			}
			notes = append(notes, t.Text)
		case ui.OK:
			if worst == ui.None {
				worst = ui.OK
			}
			good = append(good, t.Text)
		}
	}
	switch worst {
	case ui.None:
		h.Title = "Состояние защиты неизвестно"
		h.Text = "Системная служба не ответила. Настройки ниже можно менять: они сохранятся и применятся, когда служба вернётся."
		return h
	case ui.OK:
		h.Title = "Шлюз защищён"
	case ui.Warn:
		h.Title = "Шлюз защищён, есть замечания"
	default:
		h.Title = "Шлюз защищён не полностью"
	}
	h.Judged = ui.Judge(worst, securityJudgeOwner)
	h.Ring = &ui.Ring{Done: ok, Total: len(tags)}

	if len(good) > 0 {
		h.Text = upperFirst(strings.Join(good, ", ")) + "."
	}
	if len(notes) > 0 {
		h.Text += " " + ui.Plural(len(notes), "замечание", "замечания", "замечаний") + ": " + strings.Join(notes, ", ") + "."
		h.Text = strings.TrimSpace(h.Text)
	}
	return h
}

func upperFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func securityUpdatesSwitch(on, tool, paused bool, lastRun string) ui.SwitchRow {
	row := ui.SwitchRow{ID: "auto-updates", Name: "auto_updates", Checked: on, Disabled: !tool,
		Label: "Автоматические обновления"}
	switch {
	case !tool:
		row.Text = "В системе нет службы автоматических обновлений, поэтому включить их панель не может. Обратитесь в поддержку."
	case on:
		row.Text = "Панель проверяет обновления раз в сутки и ставит их сама. Если новая версия не держится, панель вернётся на прежнюю."
		if lastRun != "" {
			row.Text += " Последняя проверка: " + lastRun + "."
		}
	default:
		row.Text = "Сейчас панель обновляется только вручную. Если включить, раз в сутки система проверит обновления и установит их без вопросов; в момент установки админка недоступна около минуты. Интернет офиса, разговоры и защищённый канал не прерываются."
	}
	if paused {
		row.Tag = securityTag("на паузе по политике", ui.Warn)
	}
	return row
}

func securitySwitches(hiddenMode, ipv6 bool) (ui.SwitchRow, ui.SwitchRow) {
	hidden := ui.SwitchRow{
		ID: "hidden-mode", Name: "hidden_mode", Checked: hiddenMode,
		Label: "Скрытый режим: не отвечать на «пинг» из интернета",
		Text: "По умолчанию сервер отвечает на «пинг» с ограничением частоты: порты при этом остаются невидимыми, а поддержка провайдера видит, что линия жива. " +
			"В скрытом режиме ответа нет вовсе — при обращении «у нас не работает интернет» специалист провайдера может решить, что проблема на вашей стороне, и отказать в диагностике.",
	}
	v6 := ui.SwitchRow{
		ID: "ipv6", Name: "ipv6", Checked: ipv6,
		Label: "IPv6 на сервере",
		Tag:   securityTag("расширенная настройка", ui.None),
		Text: "Выключено по умолчанию: адреса нового поколения обходят защищённый канал, если провайдер включит их незаметно. " +
			"При включении сервер сам получит адрес IPv6 от провайдера; офису IPv6 не раздаётся ни в одном режиме. Включайте, только если понимаете, зачем это нужно.",
	}
	return hidden, v6
}

func securityDiskBar(total, avail uint64, pressure int, starved bool, usedText, totalText string) ui.UsageBar {
	bar := ui.UsageBar{Label: "Занято", Value: usedText, Of: "из " + totalText}
	if total > 0 && avail <= total {
		bar.Percent = int((total - avail) * 100 / total) //nolint:gosec
	}
	switch {
	case pressure >= 2:
		bar.Judged = ui.Judge(ui.Bad, securityJudgeOwner)
		bar.Note = "Место почти кончилось. Панель обрезает разросшиеся системные журналы сама; если не помогает — освободите место на диске."
	case pressure == 1:
		bar.Judged = ui.Judge(ui.Warn, securityJudgeOwner)
		bar.Note = "Места мало. Проверьте, что занимает диск."
	case starved:
		bar.Judged = ui.Judge(ui.Warn, securityJudgeOwner)
		bar.Note = "Диск слишком мал для обычного хранения: история панели хранится по минимуму."
	default:
		bar.Judged = ui.Judge(ui.OK, securityJudgeOwner)
		bar.Note = "Места достаточно."
	}
	return bar
}
