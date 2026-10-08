package help

import (
	"strings"
	"testing"
	"unicode"
)

func anything(string) bool { return true }

func TestCatalogIsValid(t *testing.T) {
	if err := Validate(Topics(), anything); err != nil {
		t.Fatal(err)
	}
}

func TestQuestionsAreAContract(t *testing.T) {
	want := []string{
		"Не могу войти в панель", "Панель не открывается в браузере", "В офисе нет интернета",
		"Интернет есть, а звонки плохие", "Забыл пароль диска", "Потеряно устройство входа",
		"После отключения света", "Хочу вернуть прежний роутер",
	}
	got := []string{}
	for _, topic := range Topics() {
		got = append(got, topic.Question)
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("темы: %v", got)
	}
}

func TestValidateRefusesBrokenCatalogs(t *testing.T) {
	good := func() Topic {
		return Topic{Key: "login", Question: "Вопрос", Steps: []string{"Шаг."}}
	}
	nothing := func(string) bool { return false }
	cases := map[string][]Topic{
		"имя кириллицей":        {func() Topic { x := good(); x.Key = "вход"; return x }()},
		"имя дважды":            {good(), good()},
		"нет вопроса":           {func() Topic { x := good(); x.Question = ""; return x }()},
		"нет совета":            {func() Topic { x := good(); x.Steps = nil; return x }()},
		"неизвестная проверка":  {func() Topic { x := good(); x.Checks = []Check{"weather"}; return x }()},
		"неизвестное намерение": {func() Topic { x := good(); x.Intents = []Intent{"reboot"}; return x }()},
		"неизвестный раздел":    {func() Topic { x := good(); x.Section = "nowhere"; return x }()},
	}
	for name, list := range cases {
		if Validate(list, nothing) == nil {
			t.Errorf("принят негодный каталог: %s", name)
		}
	}
	if err := Validate([]Topic{good()}, nothing); err != nil {
		t.Errorf("отвергнут годный каталог: %v", err)
	}

	many := make([]Topic, 0, 30)
	for i := 0; i < 30; i++ {
		x := good()
		x.Key = "topic-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		many = append(many, x)
	}
	if err := Validate(many, nothing); err != nil {
		t.Errorf("тридцать тем отвергнуты: %v", err)
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
	if got, ok := ByKey("login"); !ok || got.Question == "испорчено" {
		t.Error("каталог можно испортить снаружи")
	}
	if _, ok := ByKey("nowhere"); ok {
		t.Error("нашлась тема с чужим именем")
	}
}
