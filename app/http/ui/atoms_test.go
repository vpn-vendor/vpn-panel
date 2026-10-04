package ui_test

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

func atoms(t *testing.T) *template.Template {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "resources", "views", "components")
	files, err := filepath.Glob(filepath.Join(dir, "*.tmpl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("шаблоны атомов не найдены в %s: %v", dir, err)
	}
	tpl, err := template.ParseFiles(files...)
	if err != nil {
		t.Fatalf("шаблоны атомов не разбираются: %v", err)
	}
	return tpl
}

func render(t *testing.T, name string, data any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := atoms(t).ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("%s не отрисовался: %v", name, err)
	}
	return buf.String()
}

func TestAtomsCarryNoInlineAnything(t *testing.T) {
	cases := map[string]any{
		"components/field":  ui.Field{ID: "a", Name: "a", Label: "Адрес", Hint: "подсказка"},
		"components/select": ui.Select{ID: "b", Name: "b", Label: "Способ", Options: []ui.Option{{Value: "1", Label: "Один"}}},
		"components/toggle": ui.Toggle{ID: "c", Name: "c", Label: "Включить", Hint: "зачем"},
		"components/button": ui.Button{Label: "Применить"},
		"components/metric": ui.Metric{Label: "Нагрузка", Value: "0,4"},
	}
	for name, data := range cases {
		out := render(t, name, data)
		for _, forbidden := range []string{"style=\"", "onclick=", "onchange=", "onsubmit=", "javascript:"} {
			if strings.Contains(out, forbidden) {
				t.Fatalf("%s принёс запрещённое %q:\n%s", name, forbidden, out)
			}
		}
	}
}

func TestFieldLabelIsBound(t *testing.T) {
	out := render(t, "components/field", ui.Field{ID: "wan-ip", Name: "ip", Label: "Адрес"})
	if !strings.Contains(out, `for="wan-ip"`) || !strings.Contains(out, `id="wan-ip"`) {
		t.Fatalf("подпись не связана с полем:\n%s", out)
	}
}

func TestFieldErrorIsAnnounced(t *testing.T) {
	out := render(t, "components/field", ui.Field{
		ID: "vlan", Name: "vlan", Label: "Тег", Hint: "подсказка", Error: "Тег должен быть числом"})
	for _, want := range []string{`aria-invalid="true"`, `aria-describedby="vlan-error"`,
		`id="vlan-error"`, "Тег должен быть числом", "field-invalid"} {
		if !strings.Contains(out, want) {
			t.Fatalf("в ошибочном поле нет %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, "подсказка") {
		t.Fatalf("подсказка осталась рядом с ошибкой:\n%s", out)
	}
}

func TestFieldReservesRoomForMessage(t *testing.T) {
	clean := render(t, "components/field", ui.Field{ID: "a", Name: "a", Label: "Адрес"})
	if !strings.Contains(clean, `class="field-msg"`) {
		t.Fatalf("у поля без ошибки нет места под сообщение:\n%s", clean)
	}
}

func TestSelectMarksChosenOnce(t *testing.T) {
	out := render(t, "components/select", ui.Select{
		ID: "m", Name: "m", Label: "Способ", Value: "static",
		Options: []ui.Option{{Value: "dhcp", Label: "Автоматически"}, {Value: "static", Label: "Вручную"}},
	})
	if n := strings.Count(out, " selected"); n != 1 {
		t.Fatalf("отмечено вариантов: %d, ожидался один:\n%s", n, out)
	}
	if !strings.Contains(out, `value="static" selected`) {
		t.Fatalf("отмечен не тот вариант:\n%s", out)
	}
}

func TestButtonAlwaysHasTypeAndKnownKind(t *testing.T) {
	out := render(t, "components/button", ui.Button{Label: "Удалить", Kind: "danger", Small: true})
	for _, want := range []string{`type="submit"`, "btn btn-danger btn-small", "Удалить"} {
		if !strings.Contains(out, want) {
			t.Fatalf("в кнопке нет %q:\n%s", want, out)
		}
	}

	if got := (ui.Button{Kind: "кислотный"}).Class(); got != "btn" {
		t.Fatalf("неизвестный вид дал класс %q", got)
	}
}

func TestDisabledIsReal(t *testing.T) {
	if out := render(t, "components/field", ui.Field{ID: "a", Name: "a", Label: "Адрес", Disabled: true}); !strings.Contains(out, "disabled") {
		t.Fatalf("поле не отключено:\n%s", out)
	}
	if out := render(t, "components/button", ui.Button{Label: "Ждём", Disabled: true}); !strings.Contains(out, "disabled") {
		t.Fatalf("кнопка не отключена:\n%s", out)
	}
}

func TestAtomsEscapeValues(t *testing.T) {
	out := render(t, "components/field", ui.Field{
		ID: "a", Name: "a", Label: "Имя", Value: `"><script>alert(1)</script>`})
	if strings.Contains(out, "<script>") {
		t.Fatalf("значение попало в разметку неэкранированным:\n%s", out)
	}
}

func TestOneAtomPerFile(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "resources", "views", "components")
	files, _ := filepath.Glob(filepath.Join(dir, "*.tmpl"))
	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatalf("не прочитан %s: %v", f, err)
		}
		if n := strings.Count(string(body), "{{ define "); n != 1 {
			t.Fatalf("в %s объявлений атома: %d, ожидалось одно", filepath.Base(f), n)
		}
	}
}

func TestPluralSpeaksRussian(t *testing.T) {
	cases := map[int]string{1: "1 ядро", 2: "2 ядра", 4: "4 ядра", 5: "5 ядер", 11: "11 ядер",
		12: "12 ядер", 21: "21 ядро", 22: "22 ядра", 25: "25 ядер", 101: "101 ядро", 114: "114 ядер"}
	for n, want := range cases {
		if got := ui.Plural(n, "ядро", "ядра", "ядер"); got != want {
			t.Errorf("%d: %q, ждали %q", n, got, want)
		}
	}
}

func TestDangerConfirmMarksEveryRow(t *testing.T) {
	out := render(t, "components/danger-confirm", ui.DangerConfirm{Word: "RISK",
		Rows:   []ui.DangerRow{{Name: "d0", Title: "IPv6", Kind: "изменится", Warn: "второй путь"}, {Name: "d1", Title: "Подключения VPN", Item: "офис", Kind: "добавится", Warn: "чужой сервер"}},
		Submit: ui.Button{Label: "Принять риск", Kind: "danger"}})
	for _, want := range []string{`name="d0" value="1" required`, `name="d1" value="1" required`, `<mark class="danger-mark">IPv6</mark>`,
		`«офис»`, `data-word="RISK"`, `name="danger_word"`, `class="btn btn-danger"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "style=\"") || strings.Contains(out, "disabled") {
		t.Fatalf("без сценария кнопка доступна и без инлайнового стиля:\n%s", out)
	}
}

func TestFileFieldIsBound(t *testing.T) {
	out := render(t, "components/file-field", ui.FileField{ID: "f", Name: "file", Label: "Файл", Hint: "копия", Accept: ".vpnpanel", Required: true})
	for _, want := range []string{`for="f"`, `id="f"`, `type="file"`, `accept=".vpnpanel"`, `aria-describedby="f-hint"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q:\n%s", want, out)
		}
	}
}
