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
	if u := p.Viewing("internet"); u.Steps[5].State != StateCurrent {
		t.Fatalf("открыт текущий по фактам шаг — план тот же: %s", u.Steps[5].State)
	}
	if u := p.Viewing("lan"); u.Steps[5].State != StateCurrent {
		t.Fatal("скрытый шаг открыть нельзя — план тот же")
	}
	if u := p.Viewing("нет"); u.Steps[5].State != StateCurrent {
		t.Fatal("неизвестный шаг — план тот же")
	}

	if v.Current != &v.Steps[5] {
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
