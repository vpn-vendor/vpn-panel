package controllers

import (
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

func TestOverviewEveryIndicatorExplained(t *testing.T) {
	now := time.Now()
	states := map[string]overviewFacts{}

	states["защищённый режим"] = sampleFacts(true)
	states["прямой режим"] = sampleFacts(false)

	noAgent := sampleFacts(true)
	noAgent.Channel, noAgent.Online, noAgent.Updates = nil, -1, nil
	states["агент не ответил"] = noAgent

	off := sampleFacts(true)
	off.CollectOff = true
	off.Channel.Online, off.Channel.OutboundGuard = false, false
	states["сбор выключен, канал лежит"] = off

	full := sampleFacts(true)
	full.Machine = sysinfo.Machine{CPU: sysinfo.CPU{Model: "x", Threads: 4, Cores: 2}, MemBytes: 1 << 30,
		Disks: []sysinfo.Disk{{Model: "d", Bytes: 1 << 34}}, OSName: "Ubuntu", Kernel: "7.0"}
	full.Boot, full.BootOK = sysinfo.Boot{Since: now.Add(-time.Hour), For: time.Hour}, true
	full.Ports = []sysinfo.Port{{Name: "wan0", SpeedKnown: true, SpeedMbit: 100}, {Name: "lan0"}}
	full.Reliability = reliability.Snapshot{Now: now, Observed: now.Add(-30 * 24 * time.Hour), DropsWeek: 2, UncleanWeek: 1,
		FailuresDay: 1, Longest: time.Hour, LongestOK: true}
	states["паспорт и надёжность заполнены"] = full

	for name, f := range states {
		data := overviewView(f)
		for _, l := range data["lights"].(ui.StatusGrid).Lines {
			checkJudged(t, name, "светофор «"+l.Text+"»", l.Judged)
			if l.Advice == "" {
				t.Errorf("%s: у светофора «%s» нет совета", name, l.Text)
			}
			if l.Live() && (l.AdviceOK == "" || l.AdviceWarn == "" || l.AdviceBad == "" || l.AdviceUnknown == "") {
				t.Errorf("%s: живой светофор «%s» обязан нести совет на каждый уровень", name, l.Text)
			}
			if l.TextDown != "" && l.AdviceDown == "" {
				t.Errorf("%s: у светофора «%s» есть фраза «не отвечает», но нет совета к ней", name, l.Text)
			}
		}
		for _, grid := range []string{"bands", "sparks"} {
			for _, c := range data[grid].(ui.ChartGrid).Cards {
				if strings.TrimSpace(c.Note) == "" {
					t.Errorf("%s: у графика «%s» нет пояснения", name, c.Title)
				}
				if c.Scale != nil && c.Scale.Owner() == "" {
					t.Errorf("%s: у графика «%s» пороги цвета без владельца нормы", name, c.Title)
				}
			}
		}
		for _, card := range data["blocks"].(ui.CardGrid).Cards {
			if len(card.Metrics) == 0 && card.Note == "" {
				t.Errorf("%s: карточка «%s» пуста и не объясняет почему", name, card.Title)
			}
			for _, m := range card.Metrics {
				checkJudged(t, name, card.Title+" / "+m.Label, m.Judged)
				if strings.TrimSpace(m.Note) == "" {
					t.Errorf("%s: у строки «%s / %s» нет пояснения", name, card.Title, m.Label)
				}
			}
		}
		for _, key := range []string{"server", "reliability"} {
			facts := data[key].(ui.Facts)
			for _, it := range facts.Items {
				checkJudged(t, name, facts.Title+" / "+it.Label, it.Judged)
				if strings.TrimSpace(it.Note) == "" {
					t.Errorf("%s: у строки «%s / %s» нет пояснения", name, facts.Title, it.Label)
				}
			}
		}
	}
}

func checkJudged(t *testing.T, state, what string, j ui.Judgment) {
	t.Helper()
	if j.Level() != ui.None && j.Owner() == "" {
		t.Errorf("%s: «%s» окрашен без владельца нормы", state, what)
	}
}

func TestReliabilityColors(t *testing.T) {
	now := time.Now()
	f := sampleFacts(true)
	level := func(label string) ui.Level {
		it, _ := factByLabel(reliabilityFacts(f), label)
		return it.Judged.Level()
	}
	f.Reliability = reliability.Snapshot{Now: now, Observed: now.Add(-time.Hour), LongestOK: true, Longest: time.Hour}
	if level("Обрывы VPN") != ui.None || level("Отказов за сутки") != ui.None {
		t.Fatal("ноль за первый час — не доказанная норма, без цвета")
	}
	f.Reliability.Observed = now.Add(-8 * 24 * time.Hour)
	if level("Обрывы VPN") != ui.OK || level("Перезагрузок сервера за неделю") != ui.OK || level("Отказов за сутки") != ui.OK {
		t.Fatal("ноль за полную неделю — норма")
	}
	f.Reliability.DropsWeek, f.Reliability.DropsDay, f.Reliability.FailuresDay, f.Reliability.UncleanWeek, f.Reliability.RebootsWeek = 40, 40, 9, 3, 3
	for _, l := range []string{"Обрывы VPN", "Отказов за сутки", "Перезагрузок сервера за неделю"} {
		if level(l) != ui.Warn {
			t.Errorf("%s: история с отказами — «присмотреться», не %q", l, level(l))
		}
	}
	if level("Самый долгий отрезок без обрыва") != ui.None {
		t.Fatal("у самого долгого отрезка нет владельца нормы — без цвета")
	}
	f.Reliability.UncleanWeek = 0
	if level("Перезагрузок сервера за неделю") != ui.OK {
		t.Fatal("штатные перезагрузки делает администратор — не отклонение")
	}
}
