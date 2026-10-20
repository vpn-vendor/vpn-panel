package ui_test

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

func TestPultAtomsAreHonest(t *testing.T) {
	known := ui.Gauge{ID: "g", Title: "Память", Tone: ui.ToneMem, Row: "mem.used", Row2: "mem.cache", Unit: "percent", Max: 100,
		Value: 40, Value2: 30, Known: true, Note: "16 ГБ"}
	out := render(t, "components/gauge", known)
	for _, want := range []string{`data-island="chart"`, `data-kind="gauge"`, `stroke-dasharray="40.0 100"`, `stroke-dasharray="70.0 100"`,
		"40 %", `pathLength="100"`, "tone-mem"} {
		if !strings.Contains(out, want) {
			t.Errorf("кольцо потеряло %q:\n%s", want, out)
		}
	}

	empty := render(t, "components/gauge", ui.Gauge{ID: "t", Title: "Температура", Unit: "celsius", Empty: "Датчика нет"})
	if strings.Contains(empty, "data-island") || !strings.Contains(empty, "Датчика нет") || !strings.Contains(empty, ">—<") ||
		!strings.Contains(empty, `stroke-dasharray="0.0 100"`) {
		t.Errorf("пустое кольцо выдумывает:\n%s", empty)
	}
	score := render(t, "components/score-card", ui.ScoreCard{Row: "path.tunnel.mos", Good: 3.6, Poor: 3.1, Empty: "Оценка появится позже", Note: "n"})
	if !strings.Contains(score, "score-unknown") || !strings.Contains(score, `visibility="hidden"`) || !strings.Contains(score, "ещё не оценено") {
		t.Errorf("оценка без данных не говорит об этом:\n%s", score)
	}
	up := render(t, "components/uptime-card", ui.UptimeCard{Windows: []ui.UptimeWindow{
		{Key: "24h", Label: "24 часа"}, {Key: "7d", Label: "7 дней", Pct: "99,82 %", Checked: true, Cells: []string{"up", "down", "off"}}}})
	if strings.Count(up, `type="radio"`) != 2 || strings.Count(up, " checked") != 1 || !strings.Contains(up, "не наблюдался") || !strings.Contains(up, "up-down") {
		t.Errorf("доступность: окна без сценария или выдуманный процент:\n%s", up)
	}
	feed := render(t, "components/feed", ui.Feed{Cap: 7})
	if !strings.Contains(feed, "Событий пока нет") || !strings.Contains(feed, `data-cap="7"`) || !strings.Contains(feed, "<template data-feed-row>") {
		t.Errorf("лента:\n%s", feed)
	}
	for name, html := range map[string]string{"кольцо": out, "оценка": score, "доступность": up, "лента": feed} {
		for _, bad := range []string{`style="`, "onclick", "onload"} {
			if strings.Contains(html, bad) {
				t.Errorf("%s несёт инлайн %q", name, bad)
			}
		}
	}
}
