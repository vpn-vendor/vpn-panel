package controllers

import (
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
)

const (
	guessUnknown = ""
	guessAuto    = "auto"
	guessNone    = "none"
)

func providerGuess(card setup.Card, judge bool) string {
	if !judge || !card.Up {
		return guessUnknown
	}
	if card.HasRoute {
		return guessAuto
	}
	for _, a := range card.Addresses {
		if !strings.HasPrefix(a, "169.254.") {
			return guessAuto
		}
	}
	return guessNone
}

func methodNotes(guess string) []ui.WizardNote {
	auto := ui.WizardNote{Key: "dhcp", Level: ui.None, Title: "Вводить ничего не нужно",
		Text: "Шлюз попросит адрес у провайдера сам. Если интернета всё же не будет — провайдер мог привязать доступ к старому роутеру по MAC-адресу, это решается ниже."}
	switch guess {
	case guessAuto:
		auto.Level = ui.OK
		auto.Text = "Провайдер уже выдал шлюзу адрес. Если интернета всё же нет — провайдер мог привязать доступ к старому роутеру по MAC-адресу, это решается ниже."
	case guessNone:
		auto.Title = "Автоматически адрес не пришёл"
		auto.Text = "Кабель провайдера вставлен, но адрес сам не пришёл. Обычно это значит, что нужен логин и пароль из договора или доступ привязан к старому роутеру по MAC-адресу."
	}
	return []ui.WizardNote{auto,
		{Key: "pppoe", Level: ui.None, Title: "Логин и пароль — из договора",
			Text: "На рисунке договора подсвечены строки, где они обычно написаны."},
		{Key: "static", Level: ui.None, Title: "Адрес, маска и шлюз — из договора",
			Text: "На рисунке договора подсвечены строки, где они обычно написаны."},
	}
}
