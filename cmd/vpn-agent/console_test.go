package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vpn-vendor/vpn-panel-core/internal/console"
	"github.com/vpn-vendor/vpn-panel-core/internal/help"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func wired() netstatus.Status {
	return netstatus.Status{
		Interfaces:    []netstatus.Interface{{Name: "wan0", State: "UP", Addresses: []string{"198.51.100.7/24"}}},
		DefaultRoutes: []netstatus.Route{{Via: "198.51.100.1", Dev: "wan0"}},
	}
}

func healthy() gatewayFacts {
	return gatewayFacts{ServiceAnswers: true, PanelActive: true, PanelAnswers: true, Network: wired(),
		Channel: channelView{Mode: modeBlack, Present: true, Online: true, HandshakeS: 12}}
}

func levels(st console.Status) [3]console.Level {
	return [3]console.Level{st.Lines[0].Level, st.Lines[1].Level, st.Lines[2].Level}
}

func TestConsoleStatusHealthy(t *testing.T) {
	st := gatewayStatus(healthy(), numRestart)
	if st.Level != console.OK || st.Badge != "всё работает" || st.Suggest != 0 || len(st.Advice) != 0 {
		t.Fatalf("здоровый шлюз: %+v", st)
	}
	if st.Headline != "Офис в сети и выходит через защищённый канал" || levels(st) != [3]console.Level{console.OK, console.OK, console.OK} {
		t.Errorf("здоровый шлюз: %q %v", st.Headline, levels(st))
	}
}

func TestConsoleStatusSilentServiceIsNotGreen(t *testing.T) {
	f := healthy()
	f.ServiceAnswers = false
	st := gatewayStatus(f, numRestart)
	if st.Level != console.Bad || st.Suggest != numRestart {
		t.Fatalf("служба молчит: %+v", st)
	}
	if levels(st) != [3]console.Level{console.Unknown, console.Unknown, console.OK} {
		t.Errorf("служба молчит, а строки состояния: %v", levels(st))
	}
	if st.Lines[0].Text != "не удалось проверить" || st.Lines[1].Text != "не удалось проверить" {
		t.Errorf("непроверенное названо иначе: %q, %q", st.Lines[0].Text, st.Lines[1].Text)
	}
}

func TestConsoleStatusPanelDown(t *testing.T) {
	for _, change := range []func(*gatewayFacts){
		func(f *gatewayFacts) { f.PanelActive, f.PanelAnswers = false, false },
		func(f *gatewayFacts) { f.PanelAnswers = false },
	} {
		f := healthy()
		change(&f)
		st := gatewayStatus(f, numRestart)
		if st.Level != console.Bad || st.Suggest != numRestart || st.Lines[2].Level != console.Bad {
			t.Errorf("панель не отвечает: %+v", st)
		}
		if !strings.Contains(strings.Join(st.Advice, " "), "не прервётся") {
			t.Errorf("совет не говорит, что интернет в офисе не прервётся: %v", st.Advice)
		}
		if st.Lines[0].Level != console.OK || st.Lines[1].Level != console.OK {
			t.Errorf("беда панели окрасила сеть и канал: %v", levels(st))
		}
	}
}

func TestConsoleStatusChannel(t *testing.T) {
	cases := map[string]struct {
		view     channelView
		level    console.Level
		headline string
	}{
		"напрямую":            {channelView{Mode: "white"}, console.Off, "Офис выходит в интернет напрямую, без защищённого канала"},
		"настройки нечитаемы": {channelView{Mode: modeBlack, IntentBroken: true}, console.Bad, "Офис закрыт от интернета намеренно: настройки канала не читаются"},
		"переподключается":    {channelView{Mode: modeBlack, SelfHealing: true}, console.Bad, "Канал переподключается"},
		"связь пропала":       {channelView{Mode: modeBlack, Present: true, HandshakeS: 400}, console.Bad, "Связь с сервером подключения пропала"},
		"не поднят":           {channelView{Mode: modeBlack}, console.Bad, "Защищённый канал не поднят"},
	}
	for name, c := range cases {
		f := healthy()
		f.Channel = c.view
		st := gatewayStatus(f, numRestart)
		if st.Lines[1].Level != c.level || st.Headline != c.headline {
			t.Errorf("%s: уровень %v, итог %q", name, st.Lines[1].Level, st.Headline)
		}
		if c.level == console.Off && (st.Level != console.OK || st.Lines[1].Text != "выключен") {
			t.Errorf("%s: выключенный намеренно канал — не беда: %+v", name, st)
		}
		if c.level == console.Bad && (st.Level != console.Bad || len(st.Advice) == 0 || st.Badge != "нужно внимание") {
			t.Errorf("%s: беда без совета: %+v", name, st)
		}
	}
}

func TestConsoleStatusNoProvider(t *testing.T) {
	for name, network := range map[string]netstatus.Status{
		"нет маршрута": {Interfaces: wired().Interfaces},
		"кабель вынут": {Interfaces: []netstatus.Interface{{Name: "wan0", State: "DOWN", Addresses: []string{"198.51.100.7/24"}}}, DefaultRoutes: wired().DefaultRoutes},
		"нет адреса":   {Interfaces: []netstatus.Interface{{Name: "wan0", State: "UP"}}, DefaultRoutes: wired().DefaultRoutes},
	} {
		f := healthy()
		f.Network = network
		st := gatewayStatus(f, numRestart)
		if st.Lines[0].Level != console.Bad || st.Level != console.Bad {
			t.Errorf("%s: провайдер назван подключённым: %+v", name, st.Lines[0])
		}
	}
}

func TestConsoleCatalogIsValid(t *testing.T) {
	catalog := (&gateway{}).catalog()
	if err := validConsole(catalog); err != nil {
		t.Fatal(err)
	}
	want := map[int]string{1: "Код входа и адрес панели", 2: "Состояние шлюза подробно", 3: "Перезапуск панели (не интернета)",
		4: "Сведения для поддержки", 5: "Сохранить или вернуть настройки", 6: "Выйти на всех устройствах",
		9: "Помощь: что делать, если…"}
	for _, a := range catalog.Actions {
		if want[a.Number] != a.Title {
			t.Errorf("пункт %d называется «%s»: номера и названия — договор с человеком", a.Number, a.Title)
		}
		delete(want, a.Number)
	}
	if len(want) != 0 {
		t.Errorf("в меню нет пунктов: %v", want)
	}
}

func consult(f gatewayFacts, st console.Style, input string) (console.Result, string) {
	catalog := (&gateway{}).catalog()
	desk := helpDesk{actions: catalog.Actions, status: func() console.Status { return gatewayStatus(f, numRestart) }}
	var out bytes.Buffer
	res := desk.run(console.NewSession(strings.NewReader(input), &out, st, nil))
	return res, out.String()
}

func TestHelpChecksExistOnTheStatusScreen(t *testing.T) {
	keys := map[string]bool{}
	for _, line := range gatewayStatus(healthy(), numRestart).Lines {
		keys[line.Key] = true
	}
	for _, topic := range help.Topics() {
		for _, c := range topic.Checks {
			if !keys[string(c)] {
				t.Errorf("тема «%s»: проверки «%s» нет на экране состояния", topic.Question, c)
			}
		}
	}
}

func TestHelpListsEveryTopic(t *testing.T) {
	res, out := consult(healthy(), console.Style{Width: 80}, "0\n")
	if !res.Quiet {
		t.Error("«Назад» обязан вернуть в меню без ожидания Enter")
	}
	for _, topic := range help.Topics() {
		if !strings.Contains(out, "  "+topic.Question+"\n") {
			t.Errorf("в списке нет темы «%s»", topic.Question)
		}
	}
	if !strings.Contains(out, "[0-8]") || !strings.Contains(out, " 0  Назад") {
		t.Errorf("нет подсказки допустимых цифр или пути назад:\n%s", out)
	}
	if strings.Contains(out, "Дальше") {
		t.Error("восемь тем помещаются на одну страницу, а меню предлагает листать")
	}
}

func TestHelpTurnsPagesWhenTopicsOutgrowTheKeyboard(t *testing.T) {
	saved := topicsForConsole
	defer func() { topicsForConsole = saved }()
	var many []help.Topic
	for i := 0; i < 20; i++ {
		many = append(many, help.Topic{Key: fmt.Sprintf("t-%d", i), Question: fmt.Sprintf("Вопрос номер %s", strings.Repeat("и", i+1)),
			Steps: []string{"Шаг."}})
	}
	topicsForConsole = func() []help.Topic { return many }
	catalog := (&gateway{}).catalog()
	desk := helpDesk{actions: catalog.Actions, status: func() console.Status { return gatewayStatus(healthy(), numRestart) }}
	var out bytes.Buffer
	res := desk.run(console.NewSession(strings.NewReader("9\n9\n4\n"), &out, console.Style{Width: 80}, nil))
	text := out.String()
	if res.Quiet {
		t.Fatal("тема с третьей страницы не показана")
	}
	for _, want := range []string{" 9  Дальше (ещё 12)", " 9  Дальше (ещё 4)", "[0-9]", "[0-4]", many[19].Question} {
		if !strings.Contains(text, want) {
			t.Errorf("на экранах листания нет «%s»:\n%s", want, text)
		}
	}
	if strings.Count(text, "Дальше") != 2 {
		t.Errorf("на последней странице не должно быть «Дальше»: %d", strings.Count(text, "Дальше"))
	}
}

func TestHelpShowsChecksStepsAndMenuItems(t *testing.T) {
	down := healthy()
	down.PanelActive, down.PanelAnswers = false, false
	res, out := consult(down, console.Style{Width: 80}, "2\n")
	if res.Quiet {
		t.Error("тему надо дать прочитать: Enter перед возвратом в меню обязателен")
	}
	for _, want := range []string{
		"Панель не открывается в браузере", "Проверено сейчас:", "Панель управления   [остановлена]",
		"Что делать:", " 1. Проверьте адрес", " 4. Не помогло",
		"Пункты меню, которые здесь помогут:", "  1  Код входа и адрес панели", "  3  Перезапуск панели (не интернета)", "  4  Сведения для поддержки",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("на экране темы нет «%s»:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if utf8.RuneCountInString(line) > 80 {
			t.Errorf("строка шире экрана сервера: %q", line)
		}
	}
}

func TestEveryHelpTopicFitsTheServerScreen(t *testing.T) {

	const rows = 25
	for i, topic := range help.Topics() {
		_, out := consult(healthy(), console.Style{Width: 80}, strconv.Itoa(i+1)+"\n")
		at := strings.Index(out, "\n"+topic.Question+"\n")
		if at < 0 {
			t.Fatalf("тема «%s» не показана:\n%s", topic.Question, out)
		}
		if n := strings.Count(out[at+1:], "\n"); n > rows-2 {
			t.Errorf("тема «%s» занимает %d строк — не помещается на экран", topic.Question, n)
		}
		for _, line := range strings.Split(out, "\n") {
			if utf8.RuneCountInString(line) > 80 {
				t.Errorf("тема «%s»: строка шире экрана: %q", topic.Question, line)
			}
		}
	}
}

func TestHelpDoesNotCallUncheckedGreen(t *testing.T) {
	silent := healthy()
	silent.ServiceAnswers = false
	_, out := consult(silent, console.Style{Width: 80}, "3\n")
	if !strings.Contains(out, "Интернет от провайдера   [не удалось проверить]") || strings.Contains(out, "[подключён]") {
		t.Errorf("служба молчит, а тема показывает проверку пройденной:\n%s", out)
	}
}

func TestHelpOnLatinTerminalSaysWhereToRead(t *testing.T) {
	res, out := consult(healthy(), console.Style{Width: 80, Plain: true}, "1\n")
	text := out + strings.Join(res.Lines, "\n")
	for _, r := range text {
		if r > 0x7e {
			t.Fatalf("на терминале без кириллицы показан русский текст: %q", text)
		}
	}
	if len(res.Lines) == 0 || res.Quiet {
		t.Error("человеку не сказано, где читать помощь")
	}
}
