package diskcrypt

import (
	"errors"
	"testing"
)

const firstPhrase = "prezhnij-parol-diska"

func (w *world) AddKeyLike(existing, newKey []byte, like int) error {
	if w.opens(string(existing)) != like {
		return errors.New("образец не того слота")
	}
	return w.AddKey(existing, newKey)
}

func afterSetup() *world {
	w := newWorld()
	w.slots = map[int]string{0: firstPhrase}
	w.keyFile, w.conf = false, false
	w.initrds = []bool{false, false}
	return w
}

type scripted struct {
	answers []string
	told    []Message
}

func (h *scripted) Ask(Prompt) ([]byte, error) {
	if len(h.answers) == 0 {
		return nil, errors.New("человеку нечего ответить")
	}
	a := h.answers[0]
	h.answers = h.answers[1:]
	return []byte(a), nil
}

func (h *scripted) Tell(m Message) error {
	h.told = append(h.told, m)
	return nil
}

func told(h *scripted, m Message) bool {
	for _, x := range h.told {
		if x == m {
			return true
		}
	}
	return false
}

const nextPhrase = "novyj-parol-diska-2026"

func TestChangeReplacesTheOnlySlot(t *testing.T) {
	w := afterSetup()
	h := &scripted{answers: []string{firstPhrase, nextPhrase, nextPhrase}}
	out, err := Change(w, h, testPolicy(t), 3)
	if err != nil || out != Changed {
		t.Fatalf("смена: %v %v", out, err)
	}
	if len(w.slots) != 1 || w.opens(nextPhrase) < 0 || w.opens(firstPhrase) >= 0 {
		t.Fatalf("после смены один слот нового пароля, а слоты %v", w.slots)
	}
	if !told(h, MsgChanged) {
		t.Fatal("человеку не сказано, что пароль сменён")
	}
}

func TestChangeEmptyAnswerSkips(t *testing.T) {
	w := afterSetup()
	h := &scripted{answers: []string{""}}
	out, err := Change(w, h, testPolicy(t), 3)
	if err != nil || out != Skipped || w.changes != 0 || !told(h, MsgKept) {
		t.Fatalf("пустой ответ — пропуск без изменений: %v %v, изменений %d", out, err, w.changes)
	}
}

func TestChangeWrongCurrentGivesUp(t *testing.T) {
	w := afterSetup()
	h := &scripted{answers: []string{"ne-tot-1", "ne-tot-2", "ne-tot-3"}}
	out, err := Change(w, h, testPolicy(t), 3)
	if err != nil || out != GaveUp || w.changes != 0 {
		t.Fatalf("три ошибки — отмена без изменений: %v %v, изменений %d", out, err, w.changes)
	}

	w2 := afterSetup()
	h2 := &scripted{answers: []string{"ne-tot-1", "ne-tot-2", firstPhrase, nextPhrase, nextPhrase}}
	if out, err := Change(w2, h2, testPolicy(t), 3); err != nil || out != Changed {
		t.Fatalf("третья попытка должна пройти: %v %v", out, err)
	}
}

func TestChangeRejectsSamePasswordAndWeakOne(t *testing.T) {
	w := afterSetup()
	h := &scripted{answers: []string{firstPhrase, firstPhrase, firstPhrase, "short", nextPhrase, nextPhrase}}
	out, err := Change(w, h, testPolicy(t), 3)
	if err != nil || out != Changed || !told(h, MsgSame) || w.opens(nextPhrase) < 0 {
		t.Fatalf("тот же пароль и короткий отвергнуты, затем смена: %v %v %v", out, err, h.told)
	}
}

func TestChangePowerLossAtEveryPoint(t *testing.T) {
	cuts := 0
	for budget := 0; ; budget++ {
		w := afterSetup()
		w.budget = budget
		h := &scripted{answers: []string{firstPhrase, nextPhrase, nextPhrase}}
		out, err := Change(w, h, testPolicy(t), 3)
		if err == nil {
			if out != Changed || len(w.slots) != 1 || w.opens(nextPhrase) < 0 {
				t.Fatalf("без обрыва: %v, слоты %v", out, w.slots)
			}
			break
		}
		if !errors.Is(err, errCrash) {
			t.Fatalf("обрыв %d: не та ошибка: %v", budget, err)
		}
		cuts++
		if w.opens(firstPhrase) < 0 && w.opens(nextPhrase) < 0 {
			t.Fatalf("обрыв %d: диск не открывает ни прежний, ни новый пароль", budget)
		}

		cur := firstPhrase
		if w.opens(cur) < 0 {
			cur = nextPhrase
		}
		w.budget = -1
		third := "tretij-parol-diska-2026"
		h2 := &scripted{answers: []string{cur, third, third}}
		if out, err := Change(w, h2, testPolicy(t), 3); err != nil || out != Changed {
			t.Fatalf("обрыв %d: повторная смена: %v %v", budget, out, err)
		}
		if len(w.slots) != 1 || w.opens(third) < 0 {
			t.Fatalf("обрыв %d: после повторной смены слоты %v", budget, w.slots)
		}
	}
	if cuts < 2 {
		t.Fatalf("обрывов проверено %d — тест ничего не проверил", cuts)
	}
}
