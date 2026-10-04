package ui_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

func trafficCard() ui.ChartCard {
	return ui.ChartCard{
		ID: "traffic", Title: "Интернет офиса", Sub: "Сколько занято из канала", Kind: "band", Unit: "bits",
		Rows: []ui.ChartRow{
			{Name: "net.wan.rx", Label: "входящий", Value: "12,4 Мбит/с", Series: 1},
			{Name: "net.wan.tx", Label: "исходящий", Series: 2},
		},
	}
}

func TestChartAtomsCarryNoInlineAnything(t *testing.T) {
	cases := map[string]any{
		"components/chart-card":   trafficCard(),
		"components/status-line":  ui.StatusLine{ID: "s", Judged: ui.Judge(ui.OK, "очередь для звонков"), Text: "Звонки в норме", Row: "qos.wan.voice.delay", Warn: "5"},
		"components/window-chips": ui.WindowChips{},
		"components/chart-tip":    ui.ChartTip{},
	}
	for name, data := range cases {
		out := render(t, name, data)
		for _, forbidden := range []string{"style=\"", "onclick=", "onchange=", "javascript:"} {
			if strings.Contains(out, forbidden) {
				t.Fatalf("%s принёс запрещённое %q:\n%s", name, forbidden, out)
			}
		}
	}
}

func TestChartCardIsSelfDescribing(t *testing.T) {
	out := render(t, "components/chart-card", trafficCard())
	for _, want := range []string{
		`data-island="chart"`, `data-kind="band"`, `data-rows="net.wan.rx,net.wan.tx"`,
		`data-window="2h"`, `data-unit="bits"`, "12,4 Мбит/с", "chart-series-2", `data-text-paused=`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("карточка графика потеряла %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "<canvas"); n != 1 {
		t.Errorf("полотен в карточке %d, должно быть ровно одно — его отдаёт сервер", n)
	}

	if !strings.Contains(out, ">—<") {
		t.Errorf("ряд без значения обязан показывать прочерк:\n%s", out)
	}

	if strings.Contains(out, "<button") || strings.Contains(out, "chart-toggle") {
		t.Errorf("на карточке графика не должно быть кнопки раскрытия:\n%s", out)
	}
}

func TestChartCardRejectsGarbage(t *testing.T) {
	c := ui.ChartCard{ID: "x", Kind: "pie", Window: "1y", Unit: "parsec", Rows: []ui.ChartRow{
		{Name: "cpu.busy"}, {Name: "bad name"}, {Name: "a&b=c"}, {Name: "../etc"}, {Name: "UPPER"},
		{Name: "load1"}, {Name: "mem.used"}, {Name: "pressure.cpu"}, {Name: "pressure.io"},
	}}
	if got := c.RowNames(); got != "cpu.busy,load1,mem.used,pressure.cpu" {
		t.Errorf("ряды карточки: %q", got)
	}
	if c.KindName() != "spark" || c.WindowName() != "2h" || c.UnitName() != "" {
		t.Errorf("неизвестные вид, окно, единица: %q %q %q", c.KindName(), c.WindowName(), c.UnitName())
	}
	if len(ui.ChartTip{}.Slots()) != ui.MaxChartRows {
		t.Error("строк подсказки обязано быть столько же, сколько рядов на карточке")
	}
}

func TestStatusLineLivesOnlyWithRowAndThreshold(t *testing.T) {
	still := render(t, "components/status-line", ui.StatusLine{ID: "s", Judged: ui.Judge(ui.OK, "очередь для звонков"), Text: "Интернет работает"})
	if strings.Contains(still, "data-island") || !strings.Contains(still, "status-ok") || !strings.Contains(still, "Интернет работает") {
		t.Errorf("статичная фраза:\n%s", still)
	}
	live := render(t, "components/status-line", ui.StatusLine{ID: "s", Text: "Нет данных", Row: "cpu.busy", Warn: "70", Bad: "90",
		TextOK: "Сервер не перегружен", TextWarn: "Сервер загружен", TextBad: "Сервер перегружен", TextUnknown: "Нет данных"})

	path := render(t, "components/status-line", ui.StatusLine{ID: "p", Judged: ui.Judge(ui.OK, "каталог диагнозов канала"), Text: "Интернет работает", Row: "path.direct.loss",
		Alive: "path.direct.rtt", Warn: "1", TextDown: "Интернет не отвечает"})
	for _, want := range []string{`data-rows="path.direct.loss,path.direct.rtt"`, `data-alive="path.direct.rtt"`, `data-text-down="Интернет не отвечает"`} {
		if !strings.Contains(path, want) {
			t.Errorf("фраза с рядом «жив» потеряла %q:\n%s", want, path)
		}
	}
	if strings.Contains(live, "data-alive") || strings.Contains(live, "data-text-down") {
		t.Errorf("без ряда «жив» его атрибутов быть не должно:\n%s", live)
	}
	for _, want := range []string{`data-island="chart"`, `data-kind="light"`, `data-rows="cpu.busy"`, `data-warn="70"`,
		`data-text-ok="Сервер не перегружен"`, "status-unknown"} {
		if !strings.Contains(live, want) {
			t.Errorf("живая фраза потеряла %q:\n%s", want, live)
		}
	}
}

func TestRangeIsExplainedNotGuessed(t *testing.T) {
	out := render(t, "components/window-chips", ui.WindowChips{Current: "24h"})
	for _, want := range []string{`data-range-pick`, "Выбрать промежуток", "Показан отрезок",
		"Вернуть окно", `data-range-window>24 часа<`} {
		if !strings.Contains(out, want) {
			t.Errorf("объяснение отрезка потеряло %q:\n%s", want, out)
		}
	}

	for _, tag := range []string{"data-range-pick", "data-range-note"} {
		part := out[strings.Index(out, tag):]
		if !strings.Contains(part[:strings.Index(part, ">")], "hidden") {
			t.Errorf("%s обязан отдаваться скрытым", tag)
		}
	}
	panel := render(t, "components/chart-panel", ui.ChartPanel{})
	plot := panel[strings.Index(panel, "chart-panel-plot"):]
	if !strings.Contains(plot[:strings.Index(plot, "chart-panel-note")], "data-panel-coach") {
		t.Error("подсказка обязана жить у графика, а не поверх заголовка панели")
	}
	if !strings.Contains(panel, "Проведите мышью по графику") || !strings.Contains(panel, "Понятно") {
		t.Error("подсказка обязана говорить, что делать, и закрываться кнопкой")
	}
}

func TestWindowChipsHiddenAndSingleChoice(t *testing.T) {
	out := render(t, "components/window-chips", ui.WindowChips{Current: "24h"})
	if !strings.Contains(out, `data-island="chart-window" hidden`) {
		t.Errorf("чипы обязаны отдаваться скрытыми:\n%s", out)
	}
	if strings.Count(out, `aria-pressed="true"`) != 1 || !strings.Contains(out, `data-window-set="24h" aria-pressed="true"`) {
		t.Errorf("выбран обязан быть ровно один чип — 24 часа:\n%s", out)
	}
	for _, want := range []string{"2 часа", "24 часа", "7 дней"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет чипа %q", want)
		}
	}
}

func TestLayoutPrimitivesOwnTheRow(t *testing.T) {
	grid := render(t, "components/chart-grid", ui.ChartGrid{Cards: []ui.ChartCard{trafficCard(), trafficCard()}, Wide: true})
	if !strings.Contains(grid, `class="chart-grid chart-grid-wide"`) || strings.Count(grid, "<canvas") != 2 {
		t.Errorf("ряд карточек-полос:\n%s", grid[:200])
	}
	if narrow := render(t, "components/chart-grid", ui.ChartGrid{Cards: []ui.ChartCard{trafficCard()}}); !strings.Contains(narrow, `class="chart-grid"`) ||
		strings.Contains(narrow, "chart-grid-wide") {
		t.Error("обычный ряд не должен получать класс широкого")
	}
	status := render(t, "components/status-grid", ui.StatusGrid{Lines: []ui.StatusLine{{ID: "a", Text: "Интернет работает"}}})
	if !strings.Contains(status, `class="status-lines"`) || !strings.Contains(status, "Интернет работает") {
		t.Errorf("ряд светофоров:\n%s", status)
	}
	cards := render(t, "components/card-grid", ui.CardGrid{Cards: []ui.LinkCard{
		{Title: "VPN", URL: "/vpn", Metrics: []ui.Metric{{Label: "Состояние", Value: "поднят"}}},
		{Title: "Офис", URL: "/diagnostics", Note: "Число устройств сейчас получить не удалось."}}})

	for _, want := range []string{`class="overview-blocks"`, `class="card link-card"`, `href="/vpn"`, `class="metrics"`,
		`class="link-card-go"`, `aria-hidden="true"`, "поднят", "не удалось"} {
		if !strings.Contains(cards, want) {
			t.Errorf("ряд карточек-разделов потерял %q", want)
		}
	}

	if strings.Count(cards, `class="metrics"`) != 1 {
		t.Errorf("пустой ряд плиток нарисован:\n%s", cards)
	}
}

func TestChartPanelIsServedOnceWithItsCanvas(t *testing.T) {
	out := render(t, "components/chart-panel", ui.ChartPanel{})
	if !strings.HasPrefix(strings.TrimSpace(out), "<dialog") {
		t.Errorf("панель обязана быть штатным окном браузера: %.60s", strings.TrimSpace(out))
	}
	if n := strings.Count(out, "<canvas"); n != 1 {
		t.Errorf("полотен в панели %d, должно быть ровно одно", n)
	}
	for _, want := range []string{`data-island="chart-panel"`, `data-chart-select`, `data-panel-close`,
		`data-panel-reset`, `data-panel-values`, `aria-labelledby=`, "Выделите мышью отрезок"} {
		if !strings.Contains(out, want) {
			t.Errorf("панель потеряла %q", want)
		}
	}

	reset := out[strings.Index(out, "data-panel-reset"):]
	if !strings.Contains(reset[:strings.Index(reset, ">")], "hidden") {
		t.Error("кнопка возврата к полному окну обязана отдаваться скрытой")
	}
	text := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(out, " ")
	if m := regexp.MustCompile(`(?i)\b(zoom|range|reset|drag)\b`).FindString(text); m != "" {
		t.Errorf("в видимом тексте панели сырой термин %q", m)
	}
}

func TestJudgmentNeedsOwner(t *testing.T) {
	if ui.Judge(ui.Bad, "").Level() != ui.None || ui.Judge(ui.Bad, "  ").Level() != ui.None {
		t.Fatal("красный без владельца нормы")
	}
	if ui.Judge(ui.Level("purple"), "очередь").Level() != ui.None {
		t.Fatal("неизвестный уровень принят")
	}
	if j := ui.Judge(ui.Warn, "очередь"); j.Level() != ui.Warn || j.Owner() != "очередь" {
		t.Fatalf("суждение: %+v", j)
	}
	if ui.NewScale(70, 85, "") != nil || ui.NewScale(0, 0, "очередь") != nil {
		t.Fatal("пороги без владельца или без чисел")
	}
	if s := ui.NewScale(50, 0, "предохранители"); s == nil || s.Warn != "50" || s.Bad != "" {
		t.Fatalf("пороги: %+v", s)
	}
	html := render(t, "components/chart-card", ui.ChartCard{ID: "c", Title: "Процессор", Kind: "spark", Note: "n",
		Rows: []ui.ChartRow{{Name: "cpu.busy", Label: "занят"}}, Scale: ui.NewScale(70, 85, "предохранители")})
	if !strings.Contains(html, `data-warn="70"`) || !strings.Contains(html, `data-bad="85"`) {
		t.Fatalf("пороги не попали в разметку: %s", html)
	}
	line := render(t, "components/status-line", ui.StatusLine{ID: "s", Text: "Звонки в норме", Advice: "Делать ничего не нужно",
		Row: "qos.wan.voice.delay", Warn: "5", AdviceOK: "a", AdviceWarn: "b", AdviceBad: "c", AdviceUnknown: "d"})
	if !strings.Contains(line, "Делать ничего не нужно") || !strings.Contains(line, `data-advice-warn="b"`) {
		t.Fatalf("совет светофора не отрисован: %s", line)
	}
}
