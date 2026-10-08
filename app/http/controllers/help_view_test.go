package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/help"
)

func renderHelp(t *testing.T, f overviewFacts) string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, err := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	if err != nil || len(atoms) == 0 {
		t.Fatalf("атомы не найдены: %v", err)
	}
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "help.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatalf("шаблон помощи не разбирается: %v", err)
	}
	data := helpView(f)
	data["title"], data["subtitle"], data["active"], data["version"], data["searchQuery"], data["static"] = "Помощь", "", "help", "", "", "/public"
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "help.tmpl", data); err != nil {
		t.Fatalf("помощь не отрисовалась: %v", err)
	}
	return buf.String()
}

func TestHelpPageShowsEveryTopic(t *testing.T) {
	out := renderHelp(t, sampleFacts(true))
	for _, topic := range help.Topics() {
		if !strings.Contains(out, `id="`+topic.Key+`"`) || !strings.Contains(out, "<h2>"+topic.Question+"</h2>") {
			t.Errorf("темы «%s» нет на странице", topic.Question)
		}
		for _, step := range topic.Steps {
			if !strings.Contains(out, template.HTMLEscapeString(step)) {
				t.Errorf("тема «%s»: шага нет на странице: %s", topic.Question, step)
			}
		}
		if len(topic.Checks) > 0 && !strings.Contains(out, `id="check-`+topic.Key+`-`) {
			t.Errorf("тема «%s» просит проверки, а на странице их нет", topic.Question)
		}
	}
	for _, want := range []string{`href="/devices">Выдать код входа`, `href="/backup">Резервная копия`,
		`href="/diagnostics">Сведения для поддержки`, "Перезапуск панели — в меню на консоли сервера",
		"Защищённый канал поднят", "Панель отвечает"} {
		if !strings.Contains(out, want) {
			t.Errorf("на странице нет «%s»", want)
		}
	}

	if strings.Contains(out, `data-kind="light"`) {
		t.Error("проверка темы отдана живой строкой, а сценария у страницы нет")
	}
}

func TestHelpChecksTellTheTruth(t *testing.T) {
	silent := sampleFacts(true)
	silent.Channel = nil
	out := renderHelp(t, silent)
	if !strings.Contains(out, "Состояние VPN сейчас получить не удалось") || strings.Contains(out, "Защищённый канал поднят") {
		t.Error("канал без ответа назван поднятым")
	}
	direct := renderHelp(t, sampleFacts(false))
	if !strings.Contains(direct, "VPN выключен: офис выходит в интернет напрямую") {
		t.Error("при выключенном VPN проверка канала молчит")
	}
	for _, topic := range help.Topics() {
		for _, c := range topic.Checks {
			if _, ok := helpCheck(sampleFacts(true), c, topic.Key); !ok {
				t.Errorf("проверка «%s» темы «%s» не имеет строки на странице", c, topic.Question)
			}
		}
	}
}
