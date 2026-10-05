package console

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var update = flag.Bool("update", false, "переписать эталонные экраны")

func sample(calls map[string]int) Catalog {
	act := func(name string, level Level) func(*Session) Result {
		return func(*Session) Result {
			calls[name]++
			return Result{Level: level, Lines: []string{"Готово: " + name}}
		}
	}
	before := func() Result {
		return Result{Lines: []string{"Панель управления перезапустится.", "Не прервётся: интернет в офисе, звонки, защищённый канал."}}
	}
	return Catalog{
		Product: "VPN Panel — шлюз офиса", ProductEN: "VPN Panel - office gateway", Version: "0.3.1",
		Status: func() Status {
			return Status{Level: Bad, Badge: "офис без интернета", Headline: "Сервер подключения не отвечает",
				Lines: []Line{
					{Label: "Интернет от провайдера", LabelEN: "Internet", Level: OK, Text: "работает"},
					{Label: "Защищённый канал", LabelEN: "Secure channel", Level: Bad, Text: "не отвечает", Note: "7 минут"},
					{Label: "Панель управления", LabelEN: "Panel", Level: Unknown, Text: "не удалось проверить"},
				},
				Advice:  []string{"Что делать: нажмите 9 — помощь по шагам."},
				Suggest: 9}
		},
		Actions: []Action{
			{Number: 1, Command: "code", Title: "Код входа и адрес панели", TitleEN: "Login code and panel address", Run: act("code", OK)},
			{Number: 2, Command: "status", Title: "Состояние шлюза подробно", TitleEN: "Gateway status in detail", Run: act("status", OK)},
			{Number: 3, Command: "restart", Title: "Перезапуск панели (не интернета)", TitleEN: "Restart the panel (not the internet)", Danger: Ask, Before: before, Run: act("restart", OK)},
			{Number: 4, Command: "support", Title: "Сведения для поддержки", TitleEN: "Support report", Run: act("support", Bad)},
			{Number: 5, Command: "backup", Title: "Сохранить или вернуть настройки", TitleEN: "Save or restore settings", Run: act("backup", OK)},
			{Number: 6, Command: "signout", Title: "Выйти на всех устройствах", TitleEN: "Sign out on all devices", Danger: Guarded, Before: before, Run: act("signout", OK)},
			{Number: 9, Command: "help-me", Title: "Помощь: что делать, если…", TitleEN: "Help (Russian only)", Run: act("help-me", OK)},
		},
	}
}

type keyboard struct {
	keys   *strings.Reader
	screen *bytes.Buffer
}

func (k keyboard) Read(p []byte) (int, error) {
	n, err := k.keys.Read(p[:1])
	k.screen.Write(p[:n])
	return n, err
}

func talk(t *testing.T, c Catalog, st Style, input string) string {
	t.Helper()
	var out bytes.Buffer
	Run(c, NewSession(keyboard{strings.NewReader(input), &out}, &out, st, func() string { return "4821" }))
	return out.String()
}

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		t.Fatalf("нет эталона %s: go test -update", name)
	}
	if got != string(want) {
		t.Errorf("экран разошёлся с эталоном %s:\n%s", name, got)
	}
}

func TestSampleCatalogIsValid(t *testing.T) {
	if err := sample(map[string]int{}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesBrokenCatalogs(t *testing.T) {
	run := func(*Session) Result { return Result{} }
	ok := Action{Number: 1, Command: "one", Title: "Один", TitleEN: "One", Run: run}
	if (Catalog{Product: "Шлюз", ProductEN: "Gateway", Actions: []Action{ok}}).Validate() != nil {
		t.Fatal("исправный каталог отвергнут")
	}
	if (Catalog{Product: "Шлюз", Actions: []Action{ok}}).Validate() == nil {
		t.Error("каталог без названия латиницей принят")
	}
	cases := map[string][]Action{
		"цифра занята дважды":        {ok, {Number: 1, Command: "two", Title: "Два", TitleEN: "Two", Run: run}},
		"команда занята дважды":      {ok, {Number: 2, Command: "one", Title: "Два", TitleEN: "Two", Run: run}},
		"цифра выхода":               {{Number: 0, Command: "zero", Title: "Ноль", TitleEN: "Zero", Run: run}},
		"две цифры":                  {{Number: 10, Command: "ten", Title: "Десять", TitleEN: "Ten", Run: run}},
		"команда не латиницей":       {{Number: 2, Command: "код", Title: "Код", TitleEN: "Code", Run: run}},
		"нет записи латиницей":       {{Number: 2, Command: "two", Title: "Два", Run: run}},
		"латиница с кириллицей":      {{Number: 2, Command: "two", Title: "Два", TitleEN: "Два", Run: run}},
		"ничего не делает":           {{Number: 2, Command: "two", Title: "Два", TitleEN: "Two"}},
		"опасное без объяснения":     {{Number: 2, Command: "two", Title: "Два", TitleEN: "Two", Danger: Ask, Run: run}},
		"необратимое без объяснения": {{Number: 2, Command: "two", Title: "Два", TitleEN: "Two", Danger: Guarded, Run: run}},
	}
	for name, actions := range cases {
		if (Catalog{Product: "Шлюз", ProductEN: "Gateway", Actions: actions}).Validate() == nil {
			t.Errorf("%s: каталог принят", name)
		}
	}
}

func TestRangeShowsExactlyAllowedDigits(t *testing.T) {
	cases := map[string][]int{"[0-6, 9]": {9, 0, 1, 2, 3, 4, 5, 6}, "[0-1]": {0, 1}, "[0]": {0}, "[0, 2, 4-5]": {5, 4, 2, 0}}
	for want, in := range cases {
		if got := Range(in); got != want {
			t.Errorf("Range(%v) = %s, ожидалось %s", in, got, want)
		}
	}
}

func TestScreens(t *testing.T) {
	c := sample(map[string]int{})
	golden(t, "menu.txt", talk(t, c, Style{Width: 80}, "0\n"))
	golden(t, "menu-latin.txt", talk(t, c, Style{Width: 80, Plain: true}, "0\n"))
}

func TestScreenFitsOrdinaryTerminal(t *testing.T) {
	for _, st := range []Style{{Width: 80}, {Width: 200, Color: true}, {Width: 80, Plain: true}} {
		screen := sgr.ReplaceAllString(talk(t, sample(map[string]int{}), st, "3\ny\n\n6\n4821\n\n0\n"), "")
		for _, line := range strings.Split(screen, "\n") {
			if n := utf8.RuneCountInString(line); n > 80 {
				t.Errorf("строка в %d знаков шире экрана: %q", n, line)
			}
		}
	}
}

func TestYesIsGreenAndNoIsRed(t *testing.T) {
	out := talk(t, sample(map[string]int{}), Style{Width: 80, Color: true}, "3\nn\n\n0\n")
	if !strings.Contains(out, "\x1b[1;92my\x1b[0m — да, \x1b[1;91mn\x1b[0m — нет") {
		t.Error("буквы ответа не выделены: y — зелёным, n — красным")
	}
}

func TestColourIsDoubledByWords(t *testing.T) {
	coloured := talk(t, sample(map[string]int{}), Style{Width: 80, Color: true}, "0\n")
	if !strings.Contains(coloured, "\x1b[97;41m не отвечает \x1b[0m") {
		t.Error("красной плашки со словом нет")
	}
	bare := sgr.ReplaceAllString(coloured, "")
	for _, word := range []string{"работает", "не отвечает", "не удалось проверить", "офис без интернета"} {
		if !strings.Contains(bare, word) {
			t.Errorf("без цвета пропало слово состояния «%s»", word)
		}
	}
	if strings.ContainsAny(bare, "✓✗✔✘●▶") {
		t.Error("на экране значок, который экран сервера подменяет буквой")
	}
	if strings.Contains(talk(t, sample(map[string]int{}), Style{Width: 80}, "0\n"), "\x1b[") {
		t.Error("цвет ушёл туда, где его не просили")
	}
}

func TestLatinScreenHasNoCyrillic(t *testing.T) {
	for _, r := range talk(t, sample(map[string]int{}), Style{Width: 80, Plain: true}, "0\n") {
		if r > 0x7e {
			t.Fatalf("на экране без кириллицы знак %q", r)
		}
	}
}

func TestOnlyDigitsAreAnswers(t *testing.T) {
	calls := map[string]int{}
	out := talk(t, sample(calls), Style{Width: 80}, "x\n12\nд\ny\n7\n\n1\n\n0\n")
	if calls["code"] != 1 || len(calls) != 1 {
		t.Fatalf("вызовы: %v", calls)
	}
	if n := strings.Count(out, "Нужна одна цифра из [0-6, 9]."); n != 6 {
		t.Errorf("отказов с подсказкой %d, ожидалось 6", n)
	}
	if !strings.Contains(out, "Введите цифру и нажмите Enter [0-6, 9]: ") {
		t.Error("в приглашении нет допустимых цифр")
	}
}

func TestQuestionIsAnsweredByYesOrNo(t *testing.T) {
	cases := map[string]int{
		"3\ny\n\n0\n": 1, "3\nY\n\n0\n": 1, "3\nд\n\n0\n": 1,
		"3\nn\n\n0\n": 0, "3\nN\n\n0\n": 0,

		"3\nн\n\n0\n": 0,

		"3\n\n1\nyes\nт\nl\nn\n\n0\n": 0, "3\n0\n1\ny\n\n0\n": 1,
	}
	for input, want := range cases {
		calls := map[string]int{}
		out := talk(t, sample(calls), Style{Width: 80}, input)
		if calls["restart"] != want {
			t.Errorf("ввод %q: перезапусков %d, ожидалось %d", input, calls["restart"], want)
		}
		if !strings.Contains(out, "Не прервётся: интернет в офисе") || !strings.Contains(out, "y — да, n — нет") ||
			!strings.Contains(out, "Введите y или n и нажмите Enter [y/n]: ") {
			t.Errorf("ввод %q: перед вопросом нет объяснения или самого вопроса", input)
		}
		if want == 0 && !strings.Contains(out, "Отменено — ничего не изменилось.") {
			t.Errorf("ввод %q: отказ не подтверждён словами", input)
		}
	}
}

func TestIrreversibleNeedsTheShownNumber(t *testing.T) {
	for input, want := range map[string]int{"6\n\n\n0\n": 0, "6\n1\n\n0\n": 0, "6\n0\n\n0\n": 0, "6\n4822\n\n0\n": 0, "6\n4821\n\n0\n": 1} {
		calls := map[string]int{}
		talk(t, sample(calls), Style{Width: 80}, input)
		if calls["signout"] != want {
			t.Errorf("ввод %q: выполнено %d раз, ожидалось %d", input, calls["signout"], want)
		}
	}
}

func TestInputEndingMidwayChangesNothing(t *testing.T) {
	for _, input := range []string{"", "3\n", "6\n", "6\n48"} {
		calls := map[string]int{}
		talk(t, sample(calls), Style{Width: 80}, input)
		if len(calls) != 0 {
			t.Errorf("ввод %q оборвался, а действие выполнено: %v", input, calls)
		}
	}
}

func TestCommandsWithoutMenu(t *testing.T) {
	calls := map[string]int{}
	c := sample(calls)
	run := func(name, input string) (int, string) {
		var out bytes.Buffer
		code := RunCommand(c, "vpn-panel", name, NewSession(strings.NewReader(input), &out, Style{Width: 80}, func() string { return "4821" }))
		return code, out.String()
	}
	if code, _ := run("code", ""); code != ExitOK || calls["code"] != 1 {
		t.Errorf("команда кода: код %d, вызовы %v", code, calls)
	}
	if code, _ := run("support", ""); code != ExitFailed {
		t.Errorf("неудача действия не видна в коде выхода: %d", code)
	}
	if code, _ := run("restart", ""); code != ExitOK || calls["restart"] != 0 {
		t.Errorf("без ответа человека перезапуск обязан не случиться: код %d, вызовы %v", code, calls)
	}
	if code, _ := run("restart", "y\n"); code != ExitOK || calls["restart"] != 1 {
		t.Errorf("перезапуск с ответом «да»: код %d, вызовы %v", code, calls)
	}
	code, out := run("nonsense", "")
	if code != ExitUnknown || !strings.Contains(out, "Такой команды нет: nonsense") || !strings.Contains(out, "signout") {
		t.Errorf("неизвестная команда: код %d, вывод %q", code, out)
	}
	code, out = run("--help", "")
	for _, name := range c.Commands() {
		if !strings.Contains(out, "  "+name+" ") {
			t.Errorf("в справке нет команды %s", name)
		}
	}
	if code != ExitOK || !strings.Contains(out, "Использование: sudo vpn-panel [команда]") {
		t.Errorf("справка: код %d", code)
	}
}

func TestLongLinesAreFoldedByWords(t *testing.T) {
	long := "  Панель управления перезапустится: страница в браузере на несколько секунд перестанет отвечать, а потом вернётся."
	var out bytes.Buffer
	s := NewSession(strings.NewReader(""), &out, Style{Width: 80}, nil)
	s.Show(Result{Lines: []string{long, "коротко"}})
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 || lines[2] != " коротко" {
		t.Fatalf("сложено не так: %q", lines)
	}
	for _, line := range lines[:2] {
		if utf8.RuneCountInString(line) > 80 || !strings.HasPrefix(line, "   ") {
			t.Errorf("строка шире экрана или потеряла отступ: %q", line)
		}
	}
	if strings.Join(strings.Fields(lines[0]+" "+lines[1]), " ") != strings.Join(strings.Fields(long), " ") {
		t.Error("при складывании потерялись слова")
	}
}

func TestOutputToFileKeepsRussian(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	if st := Detect(w, env(map[string]string{"LANG": "C.UTF-8"})); st.Plain || st.Color {
		t.Errorf("вывод в файл при обычной локали: %+v — ни латиницы, ни цвета быть не должно", st)
	}
	if st := Detect(w, env(map[string]string{"LANG": "C"})); !st.Plain {
		t.Error("локаль без кириллицы, а подписи остались русскими")
	}
	if st := Detect(w, env(map[string]string{"LC_ALL": "ru_RU.UTF-8", "LANG": "C", "TERM": "xterm"})); st.Plain || st.Color {
		t.Errorf("вывод не в терминал: %+v", st)
	}
}

func TestWordsForTabComeFromTheCatalog(t *testing.T) {
	c := sample(map[string]int{})
	want := append(c.Commands(), "help")
	if got := c.Words(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("слова для клавиши TAB: %v, ожидалось %v", got, want)
	}
	for _, word := range []string{"help", "--help", "-h"} {
		if !IsHelp(word) {
			t.Errorf("%s не распознан как просьба о справке", word)
		}
	}
	if IsHelp("code") || IsHelp(CompleteWord) {
		t.Error("действие принято за просьбу о справке")
	}
}

func TestSuggestedItemIsMarked(t *testing.T) {
	out := talk(t, sample(map[string]int{}), Style{Width: 80}, "0\n")
	if !strings.Contains(out, "9  Помощь: что делать, если…   ← начните отсюда") {
		t.Error("пункт, с которого начать, не отмечен")
	}
}

func TestQuietResultReturnsWithoutEnter(t *testing.T) {
	c := sample(map[string]int{})
	c.Actions[4].Run = func(*Session) Result { return Result{Quiet: true} }
	const pause = "Enter — вернуться в меню"
	if out := talk(t, c, Style{Width: 80}, "5\n0\n"); strings.Contains(out, pause) {
		t.Error("человек вышел из пункта сам, а меню ждёт Enter")
	}
	if out := talk(t, c, Style{Width: 80}, "1\n\n0\n"); !strings.Contains(out, pause) {
		t.Error("итог действия не дали прочитать")
	}
}

func TestStepsContinueUnderTheText(t *testing.T) {
	var out bytes.Buffer
	s := NewSession(strings.NewReader(""), &out, Style{Width: 80}, nil)
	s.Steps([]string{
		"Панель управления перезапустится: страница в браузере на несколько секунд перестанет отвечать, а потом вернётся.",
		"Коротко.",
	})
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], " 1. Панель") || !strings.HasPrefix(lines[1], "    ") ||
		strings.HasPrefix(lines[1], "     ") || lines[2] != " 2. Коротко." {
		t.Fatalf("шаги сложены не так: %q", lines)
	}
	for _, line := range lines {
		if utf8.RuneCountInString(line) > 80 {
			t.Errorf("шаг шире экрана: %q", line)
		}
	}
}
