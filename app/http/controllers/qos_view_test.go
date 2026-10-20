package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/internal/speedtest"
)

var switchTag = regexp.MustCompile(`<input type="checkbox" id="qos-enabled"[^>]*>`)

func TestQosPageKeepsFormContract(t *testing.T) {
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"),
		filepath.Join(root, "qos.tmpl"), filepath.Join(root, "speedtest_card.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{true, false} {
		view := map[string]any{"title": "QoS", "active": "qos", "csrf": "tok", "enabled": on, "downMbit": 100, "upMbit": 50,
			"queueActive": on, "linkMbit": 1000, "cores": 4, "load1": "0,41",
			"fieldDown":   ui.Field{ID: "qos-down", Name: "down_mbit", Label: "Скачивание, Мбит/с"},
			"fieldUp":     ui.Field{ID: "qos-up", Name: "up_mbit", Label: "Отдача, Мбит/с"},
			"buttonApply": ui.Button{Label: "Применить"}, "speedBack": "/qos"}
		if on {
			view["appliedDown"], view["appliedUp"] = 95, 47
		}
		addSpeedtestView(view, qossvc.SpeedtestState{Result: &speedtest.Result{
			Down:     []speedtest.SourceResult{{Name: "Источник 1", Kbit: 96000}, {Name: "Источник 2", Kbit: 0}},
			Up:       []speedtest.SourceResult{{Name: "Источник 1", Kbit: 62000}, {Name: "Источник 2", Kbit: 0}},
			DownKbit: 94000, UpKbit: 61000, MeasuredAt: time.Now(),
		}})
		view["switchEnabled"] = qosSwitch(on)
		view["hero"] = qosHero(view)
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "qos.tmpl", view); err != nil {
			t.Fatalf("включено=%v: %v", on, err)
		}
		html := buf.String()
		want := []string{`action="/qos/apply"`, `name="enabled" value="1"`, `name="down_mbit"`, `name="up_mbit"`,
			`action="/qos/speedtest"`, `name="back" value="/qos"`, `data-fill-tariff`, `data-down="94"`, `data-up="61"`,
			"96 / 62 Мбит/с", "недоступен", "сегодня, ", "Порт в интернет", "не узкое место"}
		if on {
			want = append(want, "Приоритет разговоров работает", `<div class="metric-value">95 <span`)
		} else {
			want = append(want, "Приоритет разговоров выключен", `<div class="metric-value">—</div>`)
		}
		for _, w := range want {
			if !strings.Contains(html, w) {
				t.Fatalf("включено=%v: на странице нет %q", on, w)
			}
		}
		box := switchTag.FindString(html)
		if box == "" || on != strings.Contains(box, "checked") {
			t.Fatalf("включено=%v: переключатель не отражает состояние: %q", on, box)
		}
	}
}

func TestQosPageBeforeFirstMeasure(t *testing.T) {
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"),
		filepath.Join(root, "qos.tmpl"), filepath.Join(root, "speedtest_card.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatal(err)
	}
	view := map[string]any{"title": "QoS", "active": "qos", "csrf": "tok", "enabled": true, "downMbit": 100, "upMbit": 50,
		"fieldDown":   ui.Field{ID: "qos-down", Name: "down_mbit"},
		"fieldUp":     ui.Field{ID: "qos-up", Name: "up_mbit"},
		"buttonApply": ui.Button{Label: "Применить"}, "speedBack": "/qos"}
	addSpeedtestView(view, qossvc.SpeedtestState{})
	view["switchEnabled"] = qosSwitch(true)
	view["hero"] = qosHero(view)
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "qos.tmpl", view); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, w := range []string{"замера ещё не было", "скорость карты не определена", `action="/qos/speedtest"`} {
		if !strings.Contains(html, w) {
			t.Fatalf("на странице нет %q", w)
		}
	}
	if strings.Contains(html, "data-fill-tariff") || strings.Contains(html, "Источники замера") {
		t.Fatal("до первого замера страница предлагает подставить или показать источники")
	}
	if n := strings.Count(html, `class="metric-label"`); n != 5 {
		t.Fatalf("плиток итога %d, ждали пять: три в герое и две в замере", n)
	}
}
