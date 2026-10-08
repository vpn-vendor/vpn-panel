package controllers

import (
	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overview"
	"github.com/vpn-vendor/vpn-panel-core/internal/help"
)

type HelpController struct{}

func NewHelpController() *HelpController { return &HelpController{} }

func (c *HelpController) Index(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().View().Make("help.tmpl", page(ctx, "Помощь", "help", helpView(gatherOverview())))
}

type helpTopic struct {
	Key, Question string
	Checks        ui.StatusGrid
	Steps         []string
	Means         []helpMean
}

type helpMean struct {
	Text string
	URL  string
	Note string
}

var intentMeans = map[help.Intent]helpMean{
	help.IntentCode:    {Text: "Выдать код входа", URL: "/devices"},
	help.IntentSignOut: {Text: "Выйти на всех остальных устройствах", URL: "/devices"},
	help.IntentBackup:  {Text: "Резервная копия", URL: "/backup"},
	help.IntentSupport: {Text: "Сведения для поддержки", URL: "/diagnostics"},
	help.IntentRestart: {Text: "Перезапуск панели", Note: "в меню на консоли сервера"},
}

func helpView(f overviewFacts) map[string]any {
	topics := make([]helpTopic, 0, len(help.Topics()))
	for _, t := range help.Topics() {
		item := helpTopic{Key: t.Key, Question: t.Question, Steps: t.Steps}
		for _, c := range t.Checks {
			if line, ok := helpCheck(f, c, t.Key); ok {
				item.Checks.Lines = append(item.Checks.Lines, line)
			}
		}
		for _, intent := range t.Intents {
			if m, ok := intentMeans[intent]; ok {
				item.Means = append(item.Means, m)
			}
		}
		topics = append(topics, item)
	}
	return map[string]any{"topics": topics}
}

func helpCheck(f overviewFacts, c help.Check, key string) (ui.StatusLine, bool) {
	id := "check-" + key + "-" + string(c)
	switch c {
	case help.CheckInternet:

		line := lightLine(id, overview.Internet(f.Protected, f.Paths), f.CollectOff)
		line.Row, line.Alive, line.Warn, line.Bad = "", "", "", ""
		return line, true
	case help.CheckChannel:
		line := ui.StatusLine{ID: id}
		switch {
		case !f.Protected:
			line.Text, line.Advice = "VPN выключен: офис выходит в интернет напрямую", "Так настроено в разделе VPN."
		case f.Channel == nil:
			line.Text, line.Advice = "Состояние VPN сейчас получить не удалось", "Обновите страницу; если повторяется — откройте раздел VPN."
		case f.Channel.Online:
			line.Judged, line.Text, line.Advice = ui.Judge(ui.OK, ownerChannel), "Защищённый канал поднят", "Делать ничего не нужно."
		default:
			line.Judged, line.Text, line.Advice = ui.Judge(ui.Bad, ownerChannel), "Защищённый канал не поднят", "Причина и что делать — в разделе VPN."
		}
		return line, true
	case help.CheckPanel:
		return ui.StatusLine{ID: id, Judged: ui.Judge(ui.OK, ownerPanel), Text: "Панель отвечает", Advice: "Вы читаете её страницу — она работает."}, true
	}
	return ui.StatusLine{}, false
}

const ownerPanel = "ответ самой панели"
