package controllers

import (
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

const networkJudgeOwner = "раздел «Сеть»"

func networkTag(text string, l ui.Level) ui.Tag {
	return ui.Tag{Text: text, Judged: ui.Judge(l, networkJudgeOwner)}
}

func networkHero(rows []ifaceView, routes []netstatus.Route) ui.HeroStatus {
	var wan, lan *ifaceView
	for i := range rows {
		switch rows[i].Role {
		case netplangen.RoleWAN:
			if wan == nil {
				wan = &rows[i]
			}
		case netplangen.RoleLAN:
			if lan == nil {
				lan = &rows[i]
			}
		}
	}
	h := ui.HeroStatus{}
	switch {
	case wan == nil && lan == nil:
		h.Title = "Роли сетевых карт не назначены"
		h.Text = "Назначьте одной карте роль «Интернет», другой — «Офис»: после применения устройства офиса получат интернет и адреса автоматически."
		h.Judged = ui.Judge(ui.Warn, networkJudgeOwner)
		h.Tags = append(h.Tags, networkTag("роли не назначены", ui.Warn))
	case wan == nil:
		h.Title = "Офис на " + lan.Name + ", карта в интернет не выбрана"
		h.Text = "Без карты с ролью «Интернет» офис не выйдет в сеть. Выберите её ниже."
		h.Judged = ui.Judge(ui.Warn, networkJudgeOwner)
		h.Tags = append(h.Tags, networkTag("нет карты в интернет", ui.Warn))
	case lan == nil:
		h.Title = "Интернет через " + wan.Name + ", карта офиса не выбрана"
		h.Text = "Без карты с ролью «Офис» устройства не получат адреса. Выберите её ниже."
		h.Judged = ui.Judge(ui.Warn, networkJudgeOwner)
		h.Tags = append(h.Tags, networkTag("нет карты офиса", ui.Warn))
	default:
		h.Title = "Интернет через " + wan.Name + ", офис на " + lan.Name
		h.Text = "Устройства офиса получают интернет и адреса автоматически — на компьютерах ничего настраивать не нужно."
		h.Judged = ui.Judge(ui.OK, networkJudgeOwner)
		h.Tags = append(h.Tags, networkTag("роли назначены", ui.OK))
	}
	if len(routes) > 0 {
		h.Tags = append(h.Tags, networkTag("шлюз "+routes[0].Via+" через "+routes[0].Dev, ui.None))
	} else {
		h.Tags = append(h.Tags, networkTag("маршрута в интернет нет", ui.Bad))
		if h.Judged.Level() == ui.OK {
			h.Judged = ui.Judge(ui.Bad, networkJudgeOwner)
			h.Text = "Роли назначены, но маршрута в интернет нет: проверьте кабель и подключение к провайдеру."
		}
	}
	if lan != nil && lan.CIDR != "" {
		h.Tags = append(h.Tags, networkTag("офис "+lan.CIDR, ui.None))
	}
	return h
}

func networkMethods(w ifaceView) ui.ChoiceCards {
	m := w.WANMethod
	return ui.ChoiceCards{Name: "wanmethod_" + w.Name, Legend: "Как провайдер даёт адрес", Options: []ui.ChoiceCardOption{
		{Value: "dhcp", Label: "Автоматически", Hint: "Провайдер выдаёт адрес сам (DHCP). Так у большинства.", Checked: m == "dhcp"},
		{Value: "static", Label: "Статический адрес", Hint: "Провайдер дал адрес, маску и шлюз.", Checked: m == "static"},
		{Value: "pppoe", Label: "Логин и пароль", Hint: "PPPoE: в договоре есть имя пользователя.", Checked: m == "pppoe"},
	}}
}
