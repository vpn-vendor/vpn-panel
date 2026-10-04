package main

import (
	"context"
	"testing"
	"time"
)

func sample(sec int, out, in, rx, tx int64) dataSample {
	return dataSample{at: bootInstant(time.Duration(sec) * time.Second), echoOut: out, echoIn: in, payRx: rx, payTx: tx}
}

func TestWindowKeepsOneEdgeSample(t *testing.T) {
	var w []dataSample
	for s := 0; s <= 300; s += 15 {
		w = addSample(w, sample(s, int64(s), int64(s), 0, 0), 130)
	}
	if first := int64(w[0].at / bootInstant(time.Second)); first != 165 {
		t.Fatalf("начало окна %d с, ожидалось 165 (самое позднее не моложе 130 с)", first)
	}
}

func TestWindowRestartsOnCounterReset(t *testing.T) {
	w := addSample(nil, sample(0, 100, 100, 5000, 5000), 130)
	w = addSample(w, sample(15, 3, 0, 10, 10), 130)
	if len(w) != 1 || w[0].echoOut != 3 {
		t.Fatalf("после сброса счётчиков окно не началось заново: %+v", w)
	}
}

func TestDataEvidence(t *testing.T) {
	cases := []struct {
		name          string
		a, b          dataSample
		dead, suspect bool
	}{
		{"эхо без ответов дольше порога — данные мертвы", sample(0, 10, 10, 0, 0), sample(140, 150, 10, 0, 900), true, false},
		{"эхо с ответами — жив", sample(0, 10, 10, 0, 0), sample(140, 150, 150, 900, 900), false, false},
		{"окно короче порога — вердикта нет", sample(0, 10, 10, 0, 0), sample(100, 150, 10, 0, 900), false, false},
		{"эха нет, отправка без приёма — только подозрение", sample(0, 0, 0, 500, 500), sample(140, 0, 0, 500, 9000), false, true},
		{"эха нет, простой — ничего", sample(0, 0, 0, 500, 500), sample(140, 0, 0, 500, 500), false, false},
		{"эха нет, поток в обе стороны — ничего", sample(0, 0, 0, 500, 500), sample(140, 0, 0, 9000, 9000), false, false},
	}
	for _, c := range cases {
		dead, suspect := dataEvidence([]dataSample{c.a, c.b}, 130)
		if dead != c.dead || suspect != c.suspect {
			t.Errorf("%s: dead=%v suspect=%v", c.name, dead, suspect)
		}
	}
}

func TestRepliesRestoreBudget(t *testing.T) {
	v := &vpnApplier{}
	v.watch.DataRestarts = 2
	v.observeData(sample(0, 10, 10, 0, 0), 130)
	v.observeData(sample(15, 20, 11, 0, 0), 130)
	if v.watch.DataRestarts != 0 {
		t.Fatalf("бюджет не восстановлен: %d", v.watch.DataRestarts)
	}
}

func TestDataLadder(t *testing.T) {
	ladder := (&vpnApplier{}).ladder(context.Background(), &vpnState{})
	pick := func(in watchdogInput) string {
		if r := chooseRemedy(in, ladder); r != nil {
			return r.id
		}
		return ""
	}
	base := watchdogInput{Present: true, HandshakeOK: true, AgeSec: 5, StaleSec: 130, OnFailure: failStrict,
		DueForRetry: true, DataDead: true}
	if got := pick(base); got != "data_restart" {
		t.Fatalf("строгий режим, данные мертвы: %q, ожидался перезапуск", got)
	}
	exhausted := base
	exhausted.DataRestarts = dataRestartBudget
	if got := pick(exhausted); got != "" {
		t.Fatalf("бюджет исчерпан: %q, ожидалось бездействие (канал остаётся подключённым)", got)
	}
	direct := base
	direct.OnFailure = failDirect
	if got := pick(direct); got != "degrade" {
		t.Fatalf("режим «напрямую», данные мертвы: %q, ожидался выпуск", got)
	}
	alive := base
	alive.DataDead = false
	if got := pick(alive); got != "healthy" {
		t.Fatalf("данные идут: %q", got)
	}
}

func TestWireGuardPayload(t *testing.T) {
	for _, c := range []struct {
		name           string
		bytes, packets int64
		want           int64
	}{
		{"только поддержание связи", 640, 20, 0},
		{"эхо, 20 пакетов", 2560, 20, 1920},
		{"данные отбрасываются, приходит лишь поддержание связи", 160, 5, 0},
	} {
		if got := wgPayload(c.bytes, c.packets); got != c.want {
			t.Errorf("%s: %d, ожидалось %d", c.name, got, c.want)
		}
	}
}
