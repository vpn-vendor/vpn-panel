package wizard

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

type Fact string

const (
	FactAccount  Fact = "account"
	FactRestore  Fact = "restore"
	FactWAN      Fact = "wan"
	FactLAN      Fact = "lan"
	FactTakeover Fact = "takeover"
	FactRoles    Fact = "roles"
	FactInternet Fact = "internet"
	FactSpeed    Fact = "speed"
	FactChannel  Fact = "channel"
	FactFinished Fact = "finished"
)

type Facts struct {
	Set      map[Fact]bool
	Cards    int
	Takeover int
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

	Phase string

	Minutes int
}

type Phase struct {
	Key   string
	Title string
}

var phases = []Phase{
	{Key: "intro", Title: "Знакомство"},
	{Key: "internet", Title: "Интернет"},
	{Key: "office", Title: "Офис"},
	{Key: "protect", Title: "Защита"},
	{Key: "done", Title: "Готово"},
}

func Phases() []Phase { return append([]Phase(nil), phases...) }

var steps = []Step{
	{Key: "account", Title: ui.MainAdmin.Nom, Question: "Кто будет управлять шлюзом?",
		Hint: "Учётная запись " + ui.MainAdmin.Gen + "; это устройство станет главным доверенным.",
		Done: FactAccount, Section: "devices", Phase: "intro", Minutes: 1},
	{Key: "restore", Title: "Копия настроек", Question: "Есть файл с настройками шлюза?",
		Hint: "Если шлюз уже настраивали или настройки передали файлом — загрузите его: остальные шаги заполнятся сами.",
		Done: FactRestore, Needs: []Fact{FactAccount}, Optional: true, Section: "backup", Phase: "intro", Minutes: 1},
	{Key: "wan", Title: "Карта в интернет", Question: "Какая карта смотрит в интернет?",
		Hint: "В неё воткнут кабель провайдера или модема. Панель подсказывает ответ сама — проверьте и нажмите «Далее».",
		Done: FactWAN, Needs: []Fact{FactAccount}, Section: "network", Phase: "internet", Minutes: 1},
	{Key: "lan", Title: "Карта в офис", Question: "Какая карта смотрит в офис?",
		Hint: "В неё воткнут кабель к коммутатору или компьютерам офиса.",
		Done: FactLAN, Needs: []Fact{FactWAN}, Section: "network", Phase: "internet", Minutes: 1,
		When: func(f Facts) bool { return f.Cards > 2 }},
	{Key: "takeover", Title: "Старый шлюз", Question: "Шлюз выключит старое",
		Hint: "На сервере работает старый шлюз или похожая программа. Панель выключит отмеченное при применении настроек сети, файлы уйдут в резервную копию.",
		Done: FactTakeover, Needs: []Fact{FactWAN, FactLAN}, Section: "network", Phase: "internet", Minutes: 1,
		When: func(f Facts) bool { return f.Takeover > 0 }},
	{Key: "provider", Title: "Провайдер", Question: "Как провайдер даёт адрес?",
		Hint: "Чаще всего — автоматически. Постоянный адрес или логин с паролем написаны в договоре. Панель применит настройки и проверит связь.",
		Done: FactRoles, Needs: []Fact{FactWAN, FactLAN}, Section: "network", Phase: "internet", Minutes: 2},
	{Key: "internet", Title: "Интернет", Question: "Интернет появился?",
		Hint: "Панель наблюдает за провайдером сама. Если интернета нет, можно продолжить без него и вернуться сюда позже.",
		Done: FactInternet, Needs: []Fact{FactRoles}, Optional: true, Section: "diagnostics", Phase: "internet", Minutes: 1},
	{Key: "speed", Title: "Скорость", Question: "Какая скорость у вашего интернета?",
		Hint: "Чтобы звонки шли вперёд закачек. Проще всего нажать «Запустить замер» — панель узнает сама.",
		Done: FactSpeed, Needs: []Fact{FactRoles}, Optional: true, Section: "qos", Phase: "office", Minutes: 2},
	{Key: "channel", Title: "Канал VPN", Question: "Есть файл подключения VPN?",
		Hint: "Файл от поставщика VPN. Без него офис выходит в интернет напрямую — это тоже полноценный режим.",
		Done: FactChannel, Needs: []Fact{FactRoles}, Optional: true, Section: "vpn", Phase: "protect", Minutes: 1},
	{Key: "check", Title: "Готово", Question: "Шлюз настроен",
		Hint: "Вот что получилось. Всё это можно поменять в панели в любой момент.",
		Done: FactFinished, Needs: []Fact{FactRoles}, Section: "home", Phase: "done", Minutes: 1},
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

type PhaseState struct {
	Phase
	State  State
	Number int
}

func (p Progress) PhaseStates() []PhaseState {
	current := ""
	for _, s := range p.Steps {
		if s.State == StateCurrent {
			current = s.Phase
		}
	}
	out := make([]PhaseState, 0, len(phases))
	for i, ph := range phases {
		st, any, all := StateTodo, false, true
		for _, s := range p.Steps {
			if s.Phase != ph.Key || s.State == StateHidden {
				continue
			}
			any = true
			if s.State != StateDone {
				all = false
			}
		}
		switch {
		case ph.Key == current:
			st = StateCurrent
		case any && all:
			st = StateDone
		}
		out = append(out, PhaseState{Phase: ph, State: st, Number: i + 1})
	}
	return out
}

func PhaseTitle(key string) string {
	for _, ph := range phases {
		if ph.Key == key {
			return ph.Title
		}
	}
	return ""
}

func (p Progress) MinutesLeft() int {
	n := 0
	for _, s := range p.Steps {
		if s.State != StateHidden && s.State != StateDone {
			n += s.Minutes
		}
	}
	return n
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

	p.Finished = p.Current == nil && p.Steps[len(p.Steps)-1].State != StateHidden
	return p
}

func (p Progress) Resume() string {
	if p.Current != nil {
		return p.Current.Key
	}
	for i := len(p.Steps) - 1; i >= 0; i-- {
		if p.Steps[i].State != StateHidden {
			return p.Steps[i].Key
		}
	}
	return steps[0].Key
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
	order := map[string]int{}
	for i, ph := range phases {
		order[ph.Key] = i + 1
	}
	last := 0
	for _, s := range list {

		switch at := order[s.Phase]; {
		case at == 0:
			return fmt.Errorf("шаг «%s»: этап «%s» не объявлен", s.Key, s.Phase)
		case at < last:
			return fmt.Errorf("шаг «%s»: этап «%s» раньше предыдущего шага", s.Key, s.Phase)
		case s.Minutes <= 0:
			return fmt.Errorf("шаг «%s»: нет оценки времени", s.Key)
		default:
			last = at
		}
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
