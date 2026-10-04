package main

import (
	"encoding/json"
	"os"
	"syscall"
	"testing"
)

func traces(v bool) func() bool { return func() bool { return v } }

func TestParseStateClosedOnFailure(t *testing.T) {
	good := []byte(`{"plan":{"slug":"office","protocol":"wireguard","mode":"black","on_failure":"strict","mtu":0}}`)
	cases := []struct {
		name   string
		data   []byte
		err    error
		traces bool
		broken bool
		mode   string
		slug   string
	}{
		{name: "свежая установка", err: os.ErrNotExist, mode: modeWhite},
		{name: "файл пропал, канал поднимался", err: os.ErrNotExist, traces: true, broken: true, mode: modeBlack},
		{name: "ошибка чтения диска", err: syscall.EIO, broken: true, mode: modeBlack},
		{name: "пустой файл", data: []byte{}, broken: true, mode: modeBlack},
		{name: "обрезанный файл", data: good[:len(good)/2], broken: true, mode: modeBlack},
		{name: "мусор", data: []byte("\x00\x00\x00\x00"), broken: true, mode: modeBlack},
		{name: "незнакомый режим", data: []byte(`{"plan":{"mode":"grey"}}`), broken: true, mode: modeBlack},
		{name: "режим не записан", data: []byte(`{}`), broken: true, mode: modeBlack},
		{name: "целый защищённый", data: good, mode: modeBlack, slug: "office"},
		{name: "целый прямой", data: []byte(`{"plan":{"mode":"white","on_failure":"direct"}}`), mode: modeWhite},
	}
	for _, c := range cases {
		st := parseState(c.data, c.err, traces(c.traces))
		if st.Broken != c.broken || st.Plan.Mode != c.mode || st.Plan.Slug != c.slug {
			t.Errorf("%s: broken=%v mode=%q slug=%q, ожидалось broken=%v mode=%q slug=%q",
				c.name, st.Broken, st.Plan.Mode, st.Plan.Slug, c.broken, c.mode, c.slug)
		}
		if st.Broken && st.Plan.OnFailure != failStrict {
			t.Errorf("%s: при сбое выпуск не строгий: %q", c.name, st.Plan.OnFailure)
		}
	}
}

func TestParseStateOldReadingWouldOpen(t *testing.T) {
	old := func(data []byte, err error) string {
		if err != nil {
			return modeWhite
		}
		var st vpnState
		if jsonErr := json.Unmarshal(data, &st); jsonErr != nil {
			return modeWhite
		}
		return st.Plan.Mode
	}
	if old([]byte{}, nil) != modeWhite || old(nil, syscall.EIO) != modeWhite {
		t.Fatal("контроль не воспроизводит прежнее поведение")
	}
	if st := parseState([]byte{}, nil, traces(false)); !st.Broken {
		t.Fatal("пустой файл больше не закрывает")
	}
}

func TestBrokenStateIsNeverWritten(t *testing.T) {
	v := &vpnApplier{}
	if err := v.writeState(brokenState()); err == nil {
		t.Fatal("нечитаемое намерение записано")
	}
}

func TestSealedRefusesPages(t *testing.T) {
	c := newModeComposer()
	f := &firewallApplier{composer: c}
	if f.sealedErr() != nil {
		t.Fatal("отказ без закрытого состояния")
	}
	c.Seal()
	rerr := f.sealedErr()
	if rerr == nil || rerr.Code != codeFwSealed {
		t.Fatalf("закрытое состояние не отказывает странице: %+v", rerr)
	}
	if _, aerr := f.firewallApply([]byte(`{"plan":{}}`)); aerr == nil || aerr.Code != codeFwSealed {
		t.Fatalf("применение защиты прошло мимо закрытого состояния: %+v", aerr)
	}
	if !c.Unseal() || c.Sealed() || f.sealedErr() != nil {
		t.Fatal("выбор режима не снял закрытое состояние")
	}
	if c.Unseal() {
		t.Fatal("повторное снятие сообщило о закрытом состоянии")
	}
}
