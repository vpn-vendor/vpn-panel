package diskcrypt

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

const temp = "temporary-installer-key"

var errCrash = errors.New("питание пропало")

type world struct {
	slots   map[int]string
	next    int
	keyFile bool
	conf    bool
	initrds []bool
	knows   string
	budget  int
	changes int
	reverse bool
}

func newWorld() *world {
	return &world{slots: map[int]string{0: temp}, next: 1, keyFile: true, conf: true,
		initrds: []bool{true, true}, budget: -1}
}

func (w *world) change() error {
	if w.budget == 0 {
		return errCrash
	}
	if w.budget > 0 {
		w.budget--
	}
	w.changes++
	return nil
}

func (w *world) opens(key string) int {
	for s, k := range w.slots {
		if k == key {
			return s
		}
	}
	return -1
}

func (w *world) Slots() ([]int, error) {
	var out []int
	for s := range w.slots {
		out = append(out, s)
	}
	sort.Ints(out)
	return out, nil
}

func (w *world) SlotOpenedBy(key []byte) (int, error) { return w.opens(string(key)), nil }

func (w *world) AddKey(existing, newKey []byte) error {
	if w.opens(string(existing)) < 0 {
		return errors.New("нет разрешения")
	}
	if err := w.change(); err != nil {
		return err
	}
	w.slots[w.next] = string(newKey)
	w.next++
	return nil
}

func (w *world) KillSlot(slot int, auth []byte) error {
	if a := w.opens(string(auth)); a < 0 || a == slot || len(w.slots) < 2 {
		return errors.New("нет разрешения")
	}
	if err := w.change(); err != nil {
		return err
	}
	delete(w.slots, slot)
	return nil
}

func (w *world) RemoveKey(key []byte) error {
	s := w.opens(string(key))
	if s < 0 || len(w.slots) < 2 {
		return errors.New("последний слот не уничтожается")
	}
	if err := w.change(); err != nil {
		return err
	}
	delete(w.slots, s)
	return nil
}

func (w *world) KeyFile() ([]byte, bool, error) {
	if !w.keyFile {
		return nil, false, nil
	}
	return []byte(temp), true, nil
}

func (w *world) RemoveKeyFile() error {
	if !w.keyFile {
		return nil
	}
	if err := w.change(); err != nil {
		return err
	}
	w.keyFile = false
	return nil
}

func (w *world) RemoveKeyConf() error {
	if !w.conf {
		return nil
	}
	if err := w.change(); err != nil {
		return err
	}
	w.conf = false
	return nil
}

func (w *world) RebuildInitramfs() error {
	for n := range w.initrds {
		i := n
		if w.reverse {
			i = len(w.initrds) - 1 - n
		}
		if err := w.change(); err != nil {
			return err
		}
		w.initrds[i] = w.conf
	}
	return nil
}

func (w *world) InitramfsKey() (Presence, error) {
	n := 0
	for _, has := range w.initrds {
		if has {
			n++
		}
	}
	switch n {
	case 0:
		return KeyNowhere, nil
	case len(w.initrds):
		return KeyEverywhere, nil
	}
	return KeySome, nil
}

func (w *world) bootable() bool {
	if w.initrds[len(w.initrds)-1] && w.opens(temp) >= 0 {
		return true
	}
	return w.knows != "" && w.opens(w.knows) >= 0
}

type human struct {
	w      *world
	n      int
	answer []string
	told   []Message
}

func (h *human) Ask(p Prompt) ([]byte, error) {
	if len(h.answer) > 0 {
		a := h.answer[0]
		h.answer = h.answer[1:]
		return []byte(a), nil
	}
	if p == PromptNew {
		h.n++
	}
	pw := "zelenyj-chajnik-" + strings.Repeat("x", h.n)
	if p == PromptRepeat {
		h.w.knows = pw
	}
	return []byte(pw), nil
}

func (h *human) Tell(m Message) error {
	h.told = append(h.told, m)
	return nil
}

func testPolicy(t *testing.T) *diskpass.Policy {
	t.Helper()
	p, err := diskpass.NewPolicy(strings.NewReader("password2026!\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func finished(t *testing.T, w *world, label string) {
	t.Helper()
	slots, _ := w.Slots()
	if len(slots) != 1 || w.opens(w.knows) < 0 || w.keyFile || w.conf || w.initrds[0] || w.initrds[1] {
		t.Fatalf("%s: итог не тот: слоты %v, пароль человека открывает: %v, ключ %v, настройка %v, initramfs %v",
			label, w.slots, w.opens(w.knows) >= 0, w.keyFile, w.conf, w.initrds)
	}
}

func TestCleanRun(t *testing.T) {
	w := newWorld()
	h := &human{w: w}
	if err := Run(w, w, h, testPolicy(t)); err != nil {
		t.Fatal(err)
	}
	finished(t, w, "без обрыва")
	if h.told[0] != MsgIntro || h.told[len(h.told)-1] != MsgDone {
		t.Fatalf("человеку сказано: %v", h.told)
	}
	if err := Run(w, w, h, testPolicy(t)); err != nil || len(h.told) != 2 {
		t.Fatalf("повторный запуск после конца обязан ничего не делать: %v, сказано %v", err, h.told)
	}
}

func TestPowerLossAnywhere(t *testing.T) {
	clean := newWorld()
	if err := Run(clean, clean, &human{w: clean}, testPolicy(t)); err != nil {
		t.Fatal(err)
	}
	total := clean.changes
	for _, reverse := range []bool{false, true} {
		for first := 0; first < total; first++ {
			for second := -1; second < total; second++ {
				powerLoss(t, reverse, first, second)
			}
		}
	}
}

func powerLoss(t *testing.T, reverse bool, first, second int) {
	t.Helper()
	w := newWorld()
	w.reverse = reverse
	h := &human{w: w}
	w.budget = first
	if err := Run(w, w, h, testPolicy(t)); !errors.Is(err, errCrash) {
		t.Fatalf("обрыв после %d изменений не случился: %v", first, err)
	}
	if !w.bootable() {
		t.Fatalf("после обрыва на %d-м изменении диск не открыть (обратный порядок: %v): %+v", first, reverse, w)
	}
	w.budget = second
	if err := Run(w, w, h, testPolicy(t)); err != nil && !errors.Is(err, errCrash) {
		t.Fatalf("обрывы %d,%d: %v", first, second, err)
	}
	if !w.bootable() {
		t.Fatalf("после обрывов %d,%d диск не открыть (обратный порядок: %v): %+v", first, second, reverse, w)
	}
	w.budget = -1
	for i := 0; i < 3 && w.keyFile; i++ {
		if err := Run(w, w, h, testPolicy(t)); err != nil {
			t.Fatalf("обрывы %d,%d, досрочный запуск: %v", first, second, err)
		}
	}
	finished(t, w, "обрывы")
}

func TestAskUntilValidAndSame(t *testing.T) {
	w := newWorld()
	h := &human{w: w, answer: []string{"short", "zelenyj-chajnik-7", "zelenyj-chajnik-8"}}
	if err := Run(w, w, h, testPolicy(t)); err != nil {
		t.Fatal(err)
	}
	want := []Message{MsgIntro, ReasonMessage(diskpass.Short), MsgMismatch, MsgDone}
	if len(h.told) != len(want) {
		t.Fatalf("сказано %v, нужно %v", h.told, want)
	}
	for i := range want {
		if h.told[i] != want[i] {
			t.Fatalf("сказано %v, нужно %v", h.told, want)
		}
	}
	finished(t, w, "после ошибок ввода")
}

func TestDecide(t *testing.T) {
	cases := []struct {
		f    Facts
		want Step
	}{
		{Facts{KeyFile: false, TempSlot: -1}, StepNone},
		{Facts{KeyFile: true, TempSlot: -1, Initramfs: KeyEverywhere}, StepCleanup},
		{Facts{KeyFile: true, TempSlot: 0, Initramfs: KeyEverywhere}, StepFull},
		{Facts{KeyFile: true, TempSlot: 0, OtherSlots: []int{1}, Initramfs: KeyEverywhere}, StepFull},
		{Facts{KeyFile: true, TempSlot: 0, OtherSlots: []int{1}, Initramfs: KeySome}, StepFinish},
		{Facts{KeyFile: true, TempSlot: 0, OtherSlots: []int{1}, Initramfs: KeyNowhere}, StepFinish},
		{Facts{KeyFile: true, TempSlot: 0, Initramfs: KeyNowhere}, StepFull},
	}
	for _, c := range cases {
		if got := Decide(c.f); got != c.want {
			t.Errorf("Decide(%+v) = %d, нужно %d", c.f, got, c.want)
		}
	}
}
