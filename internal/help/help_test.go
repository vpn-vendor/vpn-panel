package help

import (
	"strings"
	"testing"
	"unicode"
)

func anything(string) bool { return true }

func TestCatalogIsValid(t *testing.T) {
	if err := Validate(Topics(), anything, anything); err != nil {
		t.Fatal(err)
	}
}

func TestNumbersAndQuestionsAreAContract(t *testing.T) {
	want := map[int]string{
		1: "Не могу войти в панель", 2: "Панель не открывается в браузере", 3: "В офисе нет интернета",
		4: "Интернет есть, а звонки плохие", 5: "Забыл пароль диска", 6: "Потеряно устройство входа",
		7: "После отключения света", 8: "Хочу вернуть прежний роутер",
	}
	for _, topic := range Topics() {
		if want[topic.Number] != topic.Question {
			t.Errorf("тема %d называется «%s»", topic.Number, topic.Question)
		}
		delete(want, topic.Number)
	}
	if len(want) != 0 {
		t.Errorf("в каталоге нет тем: %v", want)
	}
}

func TestValidateRefusesBrokenCatalogs(t *testing.T) {
	good := func() Topic {
		return Topic{Number: 1, Key: "login", Question: "Вопрос", Steps: []string{"Шаг."}}
	}
	nothing := func(string) bool { return false }
	cases := map[string][]Topic{
		"цифра вне одной клавиши":   {func() Topic { x := good(); x.Number = 10; return x }()},
		"цифра ноль занята выходом": {func() Topic { x := good(); x.Number = 0; return x }()},
		"цифра дважды":              {good(), func() Topic { x := good(); x.Key = "other"; return x }()},
		"не по порядку":             {func() Topic { x := good(); x.Number = 2; return x }(), func() Topic { x := good(); x.Key = "other"; return x }()},
		"имя кириллицей":            {func() Topic { x := good(); x.Key = "вход"; return x }()},
		"имя дважды":                {good(), func() Topic { x := good(); x.Number = 2; return x }()},
		"нет вопроса":               {func() Topic { x := good(); x.Question = ""; return x }()},
		"нет совета":                {func() Topic { x := good(); x.Steps = nil; return x }()},
		"неизвестная проверка":      {func() Topic { x := good(); x.Checks = []Check{"weather"}; return x }()},
		"неизвестное действие":      {func() Topic { x := good(); x.Actions = []string{"reboot"}; return x }()},
		"неизвестный раздел":        {func() Topic { x := good(); x.Section = "nowhere"; return x }()},
	}
	for name, list := range cases {
		if Validate(list, nothing, nothing) == nil {
			t.Errorf("принят негодный каталог: %s", name)
		}
	}
	if err := Validate([]Topic{good()}, nothing, nothing); err != nil {
		t.Errorf("отвергнут годный каталог: %v", err)
	}
}

func TestStepsCarryNoNumbersAndNoRawText(t *testing.T) {
	for _, topic := range Topics() {
		for _, text := range append([]string{topic.Question}, topic.Steps...) {
			for _, r := range text {
				if unicode.IsDigit(r) {
					t.Errorf("тема «%s»: в тексте цифра — «%s»", topic.Question, text)
					break
				}
			}
			for _, raw := range []string{"sudo", "/", "\\", "`", "systemctl", ".service", "http"} {
				if strings.Contains(text, raw) {
					t.Errorf("тема «%s»: сырой текст «%s» — «%s»", topic.Question, raw, text)
				}
			}
		}
		for _, step := range topic.Steps {
			if !strings.HasSuffix(step, ".") {
				t.Errorf("тема «%s»: шаг без точки — «%s»", topic.Question, step)
			}
		}
	}
}

func TestTopicsAreCopies(t *testing.T) {
	list := Topics()
	list[0].Question = "испорчено"
	if got, ok := ByNumber(1); !ok || got.Question == "испорчено" {
		t.Error("каталог можно испортить снаружи")
	}
	if _, ok := ByNumber(0); ok {
		t.Error("нашлась тема с цифрой выхода")
	}
}
