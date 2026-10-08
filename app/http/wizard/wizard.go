package wizard

import "fmt"

type Fact string

const (
	FactAccount  Fact = "account"
	FactRestore  Fact = "restore"
	FactWAN      Fact = "wan"
	FactLAN      Fact = "lan"
	FactRoles    Fact = "roles"
	FactInternet Fact = "internet"
	FactSpeed    Fact = "speed"
	FactChannel  Fact = "channel"
	FactFinished Fact = "finished"
)

type Facts struct {
	Set   map[Fact]bool
	Cards int
}

func (f Facts) Has(fact Fact) bool { return f.Set[fact] }

type Step struct {
	Key      string
	Title    string
	Question string
	Hint     string
	Done     Fact
	Needs    []Fact
	Optional bool
	Section  string

	When func(Facts) bool
}

var steps = []Step{
	{Key: "account", Title: "Администратор", Question: "Кто будет управлять шлюзом?",
		Hint: "Учётная запись администратора; это устройство станет главным доверенным.",
		Done: FactAccount, Section: "devices"},
	{Key: "restore", Title: "Копия настроек", Question: "Есть файл с настройками шлюза?",
		Hint: "Если шлюз уже настраивали или настройки передали файлом — загрузите его: остальные шаги заполнятся сами.",
		Done: FactRestore, Needs: []Fact{FactAccount}, Optional: true, Section: "backup"},
	{Key: "wan", Title: "Карта в интернет", Question: "Какая карта смотрит в интернет?",
		Hint: "В неё воткнут кабель провайдера или модема. Панель подсказывает ответ сама — проверьте и нажмите «Дальше».",
		Done: FactWAN, Needs: []Fact{FactAccount}, Section: "network"},
	{Key: "lan", Title: "Карта в офис", Question: "Какая карта смотрит в офис?",
		Hint: "В неё воткнут кабель к коммутатору или компьютерам офиса.",
		Done: FactLAN, Needs: []Fact{FactWAN}, Section: "network",
		When: func(f Facts) bool { return f.Cards > 2 }},
	{Key: "provider", Title: "Провайдер", Question: "Как провайдер даёт адрес?",
		Hint: "Чаще всего — автоматически. Постоянный адрес или логин с паролем написаны в договоре. Панель применит настройки и проверит связь.",
		Done: FactRoles, Needs: []Fact{FactWAN, FactLAN}, Section: "network"},
	{Key: "internet", Title: "Интернет", Question: "Интернет появился?",
		Hint: "Панель наблюдает за провайдером сама. Если интернета нет, можно продолжить без него и вернуться сюда позже.",
		Done: FactInternet, Needs: []Fact{FactRoles}, Optional: true, Section: "diagnostics"},
	{Key: "speed", Title: "Скорость", Question: "Какая скорость у вашего интернета?",
		Hint: "Чтобы звонки шли вперёд закачек. Проще всего нажать «Запустить замер» — панель узнает сама.",
		Done: FactSpeed, Needs: []Fact{FactRoles}, Optional: true, Section: "qos"},
	{Key: "channel", Title: "Канал VPN", Question: "Есть файл подключения VPN?",
		Hint: "Файл от поставщика VPN. Без него офис выходит в интернет напрямую — это тоже полноценный режим.",
		Done: FactChannel, Needs: []Fact{FactRoles}, Optional: true, Section: "vpn"},
	{Key: "check", Title: "Готово", Question: "Проверьте и откройте панель",
		Hint: "Вот что настроено. Дальше всё это можно менять в разделах панели.",
		Done: FactFinished, Needs: []Fact{FactRoles}, Section: "home"},
}

func Steps() []Step { return append([]Step(nil), steps...) }

func ByKey(key string) (Step, bool) {
	for _, s := range steps {
		if s.Key == key {
			return s, true
		}
	}
	return Step{}, false
}

type State string

const (
	StateDone    State = "done"
	StateCurrent State = "current"
	StateNext    State = "next"
	StateTodo    State = "todo"
	StateHidden  State = "hidden"
)

type Placed struct {
	Step
	State  State
	Number int
}

type Progress struct {
	Steps    []Placed
	Current  *Placed
	Done     int
	Total    int
	Finished bool
}

func (p Progress) Shown() []Placed {
	var out []Placed
	for _, s := range p.Steps {
		if s.State != StateHidden {
			out = append(out, s)
		}
	}
	return out
}

func Applicable(s Step, f Facts) bool {
	for _, need := range s.Needs {
		if !f.Has(need) {
			return false
		}
	}
	return s.When == nil || s.When(f)
}

func Plan(f Facts) Progress {
	p := Progress{}
	for _, s := range steps {
		ps := Placed{Step: s}
		if !Applicable(s, f) {
			ps.State = StateHidden
			p.Steps = append(p.Steps, ps)
			continue
		}
		p.Total++
		ps.Number = p.Total
		switch {
		case f.Has(s.Done):
			ps.State = StateDone
			p.Done++
		case p.Current == nil:
			ps.State = StateCurrent
		default:
			ps.State = StateTodo
		}
		p.Steps = append(p.Steps, ps)
		if ps.State == StateCurrent {
			p.Current = &p.Steps[len(p.Steps)-1]
		}
	}
	p.Finished = p.Current == nil
	return p
}

func (p Progress) Viewing(key string) Progress {
	opened := -1
	for i, s := range p.Steps {
		if s.Key == key && s.State != StateHidden {
			opened = i
		}
	}
	if opened < 0 || p.Steps[opened].State == StateCurrent {
		return p
	}
	out := p
	out.Steps = append([]Placed(nil), p.Steps...)
	for i := range out.Steps {
		switch {
		case i == opened:
			out.Steps[i].State = StateCurrent
		case out.Steps[i].State == StateCurrent:
			out.Steps[i].State = StateNext
		}
	}
	if p.Current != nil {
		out.Current = &out.Steps[p.Current.Number-1+hiddenBefore(p, p.Current.Number)]
	}
	return out
}

func hiddenBefore(p Progress, number int) int {
	hidden, seen := 0, 0
	for _, s := range p.Steps {
		if s.State == StateHidden {
			hidden++
			continue
		}
		seen++
		if seen == number {
			break
		}
	}
	return hidden
}

func (p Progress) Neighbours(key string) (prev, next string) {
	shown := p.Shown()
	for i, s := range shown {
		if s.Key != key {
			continue
		}
		if i > 0 {
			prev = shown[i-1].Key
		}
		if i+1 < len(shown) {
			next = shown[i+1].Key
		}
	}
	return prev, next
}

func Validate(list []Step) error {
	keys, done := map[string]bool{}, map[Fact]bool{}
	for _, s := range list {
		switch {
		case s.Key == "" || s.Title == "" || s.Question == "" || s.Done == "":
			return fmt.Errorf("шаг «%s»: нужны имя, название, вопрос и факт", s.Key)
		case keys[s.Key]:
			return fmt.Errorf("имя «%s» занято дважды", s.Key)
		case done[s.Done]:
			return fmt.Errorf("факт «%s» делает выполненными два шага", s.Done)
		}
		for _, need := range s.Needs {
			if !done[need] {
				return fmt.Errorf("шаг «%s» зависит от факта «%s», которого ещё нет", s.Key, need)
			}
		}
		keys[s.Key], done[s.Done] = true, true
	}
	return nil
}
