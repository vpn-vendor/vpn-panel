package wizard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func facts(cards int, set ...Fact) Facts {
	f := Facts{Set: map[Fact]bool{}, Cards: cards}
	for _, s := range set {
		f.Set[s] = true
	}
	return f
}

func TestRegistryIsValid(t *testing.T) {
	if err := Validate(steps); err != nil {
		t.Fatal(err)
	}
	if err := Validate([]Step{{Key: "a", Title: "a", Question: "a?", Done: "x"},
		{Key: "b", Title: "b", Question: "b?", Done: "y", Needs: []Fact{"z"}}}); err == nil {
		t.Fatal("зависимость от несуществующего факта обязана краснеть")
	}
}

func TestPlanFollowsFacts(t *testing.T) {
	p := Plan(facts(2))
	if p.Current == nil || p.Current.Key != "account" || p.Done != 0 {
		t.Fatalf("без фактов текущий шаг — учётная запись, а не %+v", p.Current)
	}
	p = Plan(facts(2, FactAccount, FactRestore, FactWAN, FactLAN, FactRoles))
	if p.Current == nil || p.Current.Key != "internet" {
		t.Fatalf("после ролей текущий шаг — интернет, а не %+v", p.Current)
	}
	for _, s := range p.Steps {
		if s.Key == "lan" && s.State != StateHidden {
			t.Fatalf("с двумя картами вопрос про карту офиса лишний: %s", s.State)
		}
	}
	p = Plan(facts(3, FactAccount, FactRestore, FactWAN))
	if p.Current == nil || p.Current.Key != "lan" {
		t.Fatalf("с тремя картами после карты в интернет спрашивается карта в офис, а не %+v", p.Current)
	}
	all := facts(2, FactAccount, FactRestore, FactWAN, FactLAN, FactRoles, FactInternet, FactSpeed, FactChannel, FactFinished)
	if p = Plan(all); !p.Finished || p.Done != p.Total {
		t.Fatalf("все факты есть — мастер пройден: %+v", p)
	}
}

func TestNumbersAreContiguous(t *testing.T) {
	p := Plan(facts(2, FactAccount))
	want := 1
	for _, s := range p.Shown() {
		if s.Number != want {
			t.Fatalf("шаг %s получил номер %d, ждали %d", s.Key, s.Number, want)
		}
		want++
	}
	if want-1 != p.Total {
		t.Fatalf("показано %d шагов, а всего %d", want-1, p.Total)
	}
	prev, next := Plan(facts(2, FactAccount, FactRestore, FactWAN, FactLAN)).Neighbours("wan")
	if prev != "restore" || next != "provider" {
		t.Fatalf("соседи шага wan: %q и %q", prev, next)
	}
}

func TestViewingMarksOpenedStep(t *testing.T) {
	p := Plan(facts(2, FactAccount, FactRestore, FactWAN, FactLAN, FactRoles))
	v := p.Viewing("wan")
	states := map[string]State{}
	for _, s := range v.Steps {
		states[s.Key] = s.State
	}
	if states["wan"] != StateCurrent || states["internet"] != StateNext || states["account"] != StateDone {
		t.Fatalf("открыт wan: ждали wan=current, internet=next, account=done, получили %v", states)
	}
	if v.Current == nil || v.Current.Key != "internet" || v.Done != p.Done || v.Total != p.Total {
		t.Fatalf("положение по фактам обязано сохраниться: %+v", v.Current)
	}
	if p.Steps[2].State != StateDone {
		t.Fatal("исходный план не должен меняться")
	}
	if u := p.Viewing("internet"); u.Steps[6].State != StateCurrent {
		t.Fatalf("открыт текущий по фактам шаг — план тот же: %s", u.Steps[6].State)
	}
	if u := p.Viewing("lan"); u.Steps[6].State != StateCurrent {
		t.Fatal("скрытый шаг открыть нельзя — план тот же")
	}
	if u := p.Viewing("нет"); u.Steps[6].State != StateCurrent {
		t.Fatal("неизвестный шаг — план тот же")
	}

	if v.Current != &v.Steps[6] {
		t.Fatal("Current после Viewing указывает на копию, а не на исходный план")
	}
}

func TestEveryStepHasATemplate(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "resources", "views", "setup")
	for _, s := range steps {
		raw, err := os.ReadFile(filepath.Join(dir, s.Key+".tmpl")) //nolint:gosec
		if err != nil {
			t.Errorf("у шага «%s» нет шаблона: %v", s.Key, err)
			continue
		}
		if !strings.Contains(string(raw), `{{ define "setup/`+s.Key+`" }}`) {
			t.Errorf("шаблон шага «%s» объявлен не под своим именем", s.Key)
		}
	}
}

func TestPhasesFollowSteps(t *testing.T) {
	bad := Steps()
	bad[2].Phase = "intro"
	bad[1].Phase = "office"
	if err := Validate(bad); err == nil {
		t.Fatal("этап назад посреди мастера принят")
	}
	noTime := Steps()
	noTime[0].Minutes = 0
	if err := Validate(noTime); err == nil {
		t.Fatal("шаг без оценки времени принят")
	}
	f := Facts{Set: map[Fact]bool{FactAccount: true, FactRestore: true}, Cards: 2}
	p := Plan(f)
	states := map[string]State{}
	for _, ph := range p.PhaseStates() {
		states[ph.Key] = ph.State
	}
	if states["intro"] != StateDone || states["internet"] != StateCurrent || states["done"] != StateTodo {
		t.Fatalf("этапы: %v", states)
	}
	if p.MinutesLeft() <= 0 || p.MinutesLeft() >= Plan(Facts{Set: map[Fact]bool{}, Cards: 2}).MinutesLeft()+1 {
		t.Fatalf("осталось минут: %d", p.MinutesLeft())
	}
	if PhaseTitle("protect") != "Защита" {
		t.Fatal("название этапа не найдено")
	}
}

func TestResumeWhenStuck(t *testing.T) {
	f := Facts{Set: map[Fact]bool{FactAccount: true, FactRestore: true, FactWAN: true}, Cards: 1}
	p := Plan(f)
	if p.Current != nil {
		t.Fatalf("текущий шаг %q, ждали упор", p.Current.Key)
	}
	if got := p.Resume(); got != "wan" {
		t.Errorf("Resume = %q, ждали wan", got)
	}
	if p.Finished {
		t.Error("упёршийся мастер не пройден")
	}
	done := Facts{Set: map[Fact]bool{}, Cards: 2}
	for _, s := range Steps() {
		done.Set[s.Done] = true
	}
	if p := Plan(done); !p.Finished || p.Resume() != "check" {
		t.Errorf("пройденный мастер: Finished=%v Resume=%q", p.Finished, p.Resume())
	}
}

func TestTakeoverStepFollowsPlan(t *testing.T) {
	f := facts(2, FactAccount, FactRestore, FactWAN, FactLAN)
	if p := Plan(f); p.Current == nil || p.Current.Key != "provider" {
		t.Fatalf("без пунктов плана шаг старого скрыт: %+v", p.Current)
	}
	f.Takeover = 3
	p := Plan(f)
	if p.Current == nil || p.Current.Key != "takeover" {
		t.Fatalf("с пунктами плана шаг старого обязателен: %+v", p.Current)
	}
	if prev, next := p.Neighbours("takeover"); prev != "wan" || next != "provider" {
		t.Fatalf("соседи шага старого: %q и %q", prev, next)
	}
	f.Set[FactTakeover] = true
	if p := Plan(f); p.Current == nil || p.Current.Key != "provider" {
		t.Fatalf("после согласия — провайдер: %+v", p.Current)
	}
}
