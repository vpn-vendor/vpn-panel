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
		"components/stepper": ui.Stepper{Total: 2, Current: 2, Items: []ui.StepperItem{
			{Key: "a", Title: "Первый", State: "done", URL: "/setup/a"}, {Key: "b", Title: "Второй", State: "current"}}},
		"components/choice": ui.Choice{Name: "card", Options: []ui.ChoiceOption{
			{Value: "x", Label: "Икс", Checked: true, Facts: []string{"кабель воткнут"}}, {Value: "y", Label: "Игрек", Reveals: "y"}}},
		"components/choice-card": ui.ChoiceCards{Name: "profile", Form: "f", Options: []ui.ChoiceCardOption{
			{Value: "a", Label: "Основное", Meta: "WireGuard", Checked: true, Tags: []ui.Tag{{Text: "действует", Judged: ui.Judge(ui.OK, "тест")}}}, {Value: "b", Label: "Запасное"}}},
		"components/hero-status": ui.HeroStatus{Title: "Канал поднят", Text: "подпись", Judged: ui.Judge(ui.OK, "тест"),
			Metrics: []ui.Metric{{Label: "Задержка", Value: "24", Unit: "мс"}}},
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

func TestChoiceAndStepperContracts(t *testing.T) {
	out := render(t, "components/choice", ui.Choice{Name: "card", Options: []ui.ChoiceOption{
		{Value: "x", Label: "Икс", Checked: true, Facts: []string{"кабель воткнут"}}, {Value: "y", Label: "Игрек"}}})
	if strings.Count(out, " checked") != 1 || !strings.Contains(out, `for="card-x"`) || !strings.Contains(out, `id="card-x"`) {
		t.Fatalf("выбор варианта нарушил договор:\n%s", out)
	}
	if !strings.Contains(out, "кабель воткнут") {
		t.Fatal("факты варианта потеряны")
	}
	out = render(t, "components/stepper", ui.Stepper{Total: 2, Current: 2, Items: []ui.StepperItem{
		{Key: "a", Title: "Первый", State: "done", URL: "/setup/a"}, {Key: "b", Title: "Второй", State: "current"}}})
	if !strings.Contains(out, `href="/setup/a"`) || !strings.Contains(out, `aria-current="step"`) || !strings.Contains(out, "из 2") {
		t.Fatalf("полоса шагов нарушила договор:\n%s", out)
	}
}

func TestChoiceCardsContract(t *testing.T) {
	out := render(t, "components/choice-card", ui.ChoiceCards{Name: "profile", Legend: "Подключение", Form: "vpn-apply",
		Options: []ui.ChoiceCardOption{
			{Value: "a", Label: "Основное", Meta: "WireGuard по UDP", Checked: true,
				Tags: []ui.Tag{{Text: "действует", Judged: ui.Judge(ui.OK, "тест")}, {Text: "не весь трафик", Judged: ui.Judge(ui.Warn, "тест")}}},
			{Value: "b", Label: "Запасное", Disabled: true}}})
	for _, want := range []string{`for="profile-a"`, `id="profile-a"`, `form="vpn-apply"`, `aria-label="Подключение"`,
		`class="tag tag-ok"`, `class="tag tag-warn"`, " disabled", "WireGuard по UDP"} {
		if !strings.Contains(out, want) {
			t.Fatalf("карточки-радио потеряли %q:\n%s", want, out)
		}
	}
	if strings.Count(out, " checked") != 1 {
		t.Fatalf("отмечен не ровно один вариант:\n%s", out)
	}

	if got := (ui.Tag{Text: "факт"}).Class(); got != "tag" {
		t.Fatalf("метка без суждения получила класс %q", got)
	}
}

func TestHeroStatusContract(t *testing.T) {
	out := render(t, "components/hero-status", ui.HeroStatus{Title: "Канал поднят", Text: "Весь офис через канал.",
		Judged: ui.Judge(ui.OK, "тест"), Metrics: []ui.Metric{{Label: "Задержка", Value: "24", Unit: "мс", Note: "годится для звонков"}}})
	for _, want := range []string{`class="hero hero-ok"`, "Канал поднят", "Весь офис через канал.", `class="metric"`, "годится для звонков"} {
		if !strings.Contains(out, want) {
			t.Fatalf("герой состояния потерял %q:\n%s", want, out)
		}
	}
	if got := (ui.HeroStatus{Title: "Неизвестно"}).Class(); got != "hero" {
		t.Fatalf("герой без суждения получил класс %q", got)
	}
}

func TestSwitchRowContract(t *testing.T) {
	out := render(t, "components/switch-row", ui.SwitchRow{ID: "hidden-mode", Name: "hidden_mode", Label: "Скрытый режим",
		Text: "что даёт", Checked: true, Tag: ui.Tag{Text: "расширенная"}})
	for _, want := range []string{`type="checkbox"`, `id="hidden-mode"`, `for="hidden-mode"`, `name="hidden_mode"`, `value="1"`,
		" checked", `aria-labelledby="hidden-mode-title"`, `aria-describedby="hidden-mode-text"`, "включено", "выключено", `class="tag"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("строка с переключателем потеряла %q:\n%s", want, out)
		}
	}
	if strings.Contains(render(t, "components/switch-row", ui.SwitchRow{ID: "x", Name: "x", Label: "Икс"}), " checked") {
		t.Fatal("выключенная строка отмечена")
	}
}

func TestUsageBarContract(t *testing.T) {
	out := render(t, "components/usage-bar", ui.UsageBar{Label: "Диск", Value: "27 ГБ", Of: "из 30 ГБ", Percent: 88,
		Judged: ui.Judge(ui.Warn, "тест"), Note: "места мало"})
	for _, want := range []string{`class="usage usage-warn"`, "pool-fill-90", `aria-label="Диск: 88 %"`, "из 30 ГБ", "места мало"} {
		if !strings.Contains(out, want) {
			t.Fatalf("полоса занятости потеряла %q:\n%s", want, out)
		}
	}
	for pct, step := range map[int]int{-5: 0, 0: 0, 2: 0, 3: 5, 48: 50, 100: 100, 140: 100} {
		if got := (ui.UsageBar{Percent: pct}).Step(); got != step {
			t.Errorf("доля %d дала ступень %d, ждали %d", pct, got, step)
		}
	}
}

func TestItemCardAndTimelineContracts(t *testing.T) {
	out := render(t, "components/item-grid", ui.ItemGrid{Items: []ui.ItemCard{{
		Title: "Ноутбук", Tags: []ui.Tag{{Text: "главное", Judged: ui.Judge(ui.OK, "тест")}},
		Meta: []string{"адрес 10.0.0.2"}, Note: "примечание",
		Actions: []ui.ActionForm{{Action: "/devices/revoke", CSRF: "tok", Hidden: map[string]string{"device_id": "7"},
			Button: ui.Button{Label: "Отозвать", Kind: "danger", Small: true}, Question: "Точно?"}},
	}, {Title: "Старый", Muted: true}}})
	for _, want := range []string{`class="item-card"`, `class="item-card item-muted"`, `class="tag tag-ok"`, "адрес 10.0.0.2", "примечание",
		`action="/devices/revoke"`, `name="_csrf" value="tok"`, `name="device_id" value="7"`, `data-island="confirm-action"`, `data-question="Точно?"`,
		`class="btn btn-danger btn-small"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("карточка сущности потеряла %q:\n%s", want, out)
		}
	}
	tl := render(t, "components/timeline", ui.Timeline{Days: []ui.TimelineDay{{Title: "Сегодня", Events: []ui.TimelineEvent{
		{Time: "09:41", Title: "Выдан код", Text: "адрес 10.0.0.2", Judged: ui.Judge(ui.OK, "тест")},
		{Time: "03:12", Title: "Неверный код", Extra: "повторялось ещё 4 раз", Judged: ui.Judge(ui.Warn, "тест")},
		{Time: "01:00", Title: "Факт"}}}}})
	for _, want := range []string{`class="tl-day">Сегодня`, `class="tl-event tl-ok"`, `class="tl-event tl-warn"`, `class="tl-event">`,
		"повторялось ещё 4 раз", `<time class="tl-time">09:41</time>`} {
		if !strings.Contains(tl, want) {
			t.Fatalf("лента потеряла %q:\n%s", want, tl)
		}
	}
	if !strings.Contains(render(t, "components/timeline", ui.Timeline{Empty: "пусто"}), "пусто") {
		t.Fatal("пустая лента молчит")
	}
}

func TestItemCardCarriesUsageBar(t *testing.T) {
	out := render(t, "components/item-card", ui.ItemCard{Title: "Офис",
		Bar: &ui.UsageBar{Label: "Занято", Value: "44", Of: "из 151", Percent: 29, Judged: ui.Judge(ui.OK, "тест")}})
	for _, want := range []string{`class="usage usage-ok"`, "pool-fill-30", "из 151"} {
		if !strings.Contains(out, want) {
			t.Fatalf("карточка потеряла полосу %q:\n%s", want, out)
		}
	}
	if strings.Contains(render(t, "components/item-card", ui.ItemCard{Title: "Без полосы"}), "usage") {
		t.Fatal("карточка без полосы рисует полосу")
	}
}
