package controllers

import (
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

const (
	diagJudgeOwner     = "каталог диагнозов сети"
	diagPageJudgeOwner = "раздел «Диагностика»"
)

func diagHero(level string, probedAt string, devices []deviceRow, known bool) ui.HeroStatus {
	h := ui.HeroStatus{}
	if !known {
		h.Title = "Состояние сети офиса неизвестно"
		h.Text = "Системная служба не ответила. Настройки ниже можно менять."
		return h
	}
	switch level {
	case string(ui.Bad):
		h.Title = "В сети офиса есть проблема"
		h.Text = "Ниже — что именно сломано и что делать. Красное мешает звонкам или защите прямо сейчас."
	case string(ui.Warn):
		h.Title = "В сети офиса есть на что посмотреть"
		h.Text = "Ниже — что заметил сервер. Жёлтое — устройство не отвечало или панель им не управляет."
	default:
		h.Title = "Со стороны сети признаков проблем нет"
		h.Text = "Карта локальной сети сервера работает без ошибок, известные устройства отвечают."
	}
	h.Judged = ui.Judge(ui.Level(level), diagJudgeOwner)
	if probedAt != "" {
		h.Text += " Последняя проверка сети: " + probedAt + "."
	} else {
		h.Text += " Проверку сети офиса ещё не запускали."
	}

	online, warn, bad := 0, 0, 0
	for _, d := range devices {
		if d.Online {
			online++
		}
		switch d.Level {
		case string(ui.Warn):
			warn++
		case string(ui.Bad):
			bad++
		}
	}
	tag := func(text string, l ui.Level) ui.Tag {
		return ui.Tag{Text: text, Judged: ui.Judge(l, diagPageJudgeOwner)}
	}
	h.Tags = append(h.Tags, tag(ui.Plural(len(devices), "устройство", "устройства", "устройств"), ui.None))
	h.Tags = append(h.Tags, tag("в сети: "+ui.Plural(online, "устройство", "устройства", "устройств"), ui.OK))
	if off := len(devices) - online; off > 0 {
		h.Tags = append(h.Tags, tag("не в сети: "+ui.Plural(off, "устройство", "устройства", "устройств"), ui.None))
	}
	if warn > 0 {
		h.Tags = append(h.Tags, tag("присмотреться: "+ui.Plural(warn, "устройство", "устройства", "устройств"), ui.Warn))
	}
	if bad > 0 {
		h.Tags = append(h.Tags, tag("с проблемой: "+ui.Plural(bad, "устройство", "устройства", "устройств"), ui.Bad))
	}
	return h
}

func diagSwitches(activeProbes, selfLabel bool) (ui.SwitchRow, ui.SwitchRow) {
	probes := ui.SwitchRow{
		ID: "active-probes", Name: "active_probes", Checked: activeProbes,
		Label: "Активные проверки разрешены",
		Text: "Кнопка «Проверить сеть офиса» и тест скорости до сервера. Наблюдение за сетью идёт только чтением счётчиков — " +
			"сервер не отправляет ни одного пакета сам по себе; активные проверки запускаются только по кнопке, к известным устройствам, с ограничением частоты и времени.",
	}
	labels := ui.SwitchRow{
		ID: "self-label", Name: "self_label", Checked: selfLabel,
		Label: ui.JuniorAdmin.Plural + " могут предлагать подписи",
		Text:  "На странице «Это я» " + ui.JuniorAdmin.Nom + " подписывает свой компьютер; подпись появляется здесь на проверку и действует только после принятия.",
	}
	return probes, labels
}
