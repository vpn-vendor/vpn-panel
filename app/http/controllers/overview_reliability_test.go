package controllers

import (
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
)

func factByLabel(fs ui.Facts, label string) (ui.Fact, bool) {
	for _, f := range fs.Items {
		if f.Label == label {
			return f, true
		}
	}
	return ui.Fact{}, false
}

func TestReliabilityFactsHonesty(t *testing.T) {
	now := time.Now()

	f := sampleFacts(true)
	if fs := reliabilityFacts(f); len(fs.Items) != 1 || fs.Items[0].Value != "" {
		t.Fatalf("без журнала запусков счётчики не показываются: %+v", fs.Items)
	}

	f.Reliability = reliability.Snapshot{Now: now, Observed: now.Add(-2 * time.Hour), DropsDay: 1, DropsWeek: 1,
		Longest: 90 * time.Minute, LongestOK: true, RebootsWeek: 0, FailuresDay: 2}
	fs := reliabilityFacts(f)
	if obs, ok := factByLabel(fs, "Наблюдение"); !ok || !strings.HasPrefix(obs.Value, "с ") {
		t.Fatalf("неполная неделя обязана быть названа: %+v", fs.Items)
	}
	if d, _ := factByLabel(fs, "Обрывы VPN"); d.Value != "1 за сутки, 1 за неделю" {
		t.Fatalf("обрывы: %+v", d)
	}
	if l, _ := factByLabel(fs, "Самый долгий отрезок без обрыва"); l.Value != "1 ч 30 мин" {
		t.Fatalf("отрезок: %+v", l)
	}
	if e, _ := factByLabel(fs, "Отказов за сутки"); e.Value != "2" {
		t.Fatalf("отказы: %+v", e)
	}

	f.Reliability.Observed = now.Add(-30 * 24 * time.Hour)
	f.Reliability.UncleanWeek = 1
	fs = reliabilityFacts(f)
	if _, ok := factByLabel(fs, "Наблюдение"); ok {
		t.Fatal("полная неделя не помечается как неполная")
	}
	if r, _ := factByLabel(fs, "Перезагрузок сервера за неделю"); !strings.Contains(r.Note, "без штатной остановки: 1") {
		t.Fatalf("нештатное выключение обязано быть названо: %+v", r)
	}

	direct := sampleFacts(false)
	direct.Reliability = reliability.Snapshot{Now: now, Observed: now.Add(-30 * 24 * time.Hour)}
	if d, _ := factByLabel(reliabilityFacts(direct), "Обрывы VPN"); d.Value != "" || !strings.Contains(d.Note, "VPN выключен") {
		t.Fatalf("в прямом режиме обрывы не считаются: %+v", d)
	}
	if strings.Contains(renderOverview(t, f), "Надёжность") == false {
		t.Fatal("карточка «Надёжность» не отрисовалась на обзоре")
	}
}
