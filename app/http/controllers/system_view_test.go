package controllers

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/oswindow"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

func row(t *testing.T, f ui.Facts, label string) ui.Fact {
	t.Helper()
	for _, it := range f.Items {
		if it.Label == label {
			return it
		}
	}
	t.Fatalf("нет строки %q", label)
	return ui.Fact{}
}

func jammyReport(until time.Time, facts ...hostcaps.Fact) system.Report {
	rel, _ := oswindow.Find("jammy")
	return system.Report{Release: rel, SupportUntil: until, Status: hostcaps.Status{Snapshot: hostcaps.Snapshot{
		TakenAt: "2026-10-19T12:00:00Z", Facts: facts,
		Versions: map[string]string{"os": "22.04 jammy", "kernel": "5.15", "vpn-panel": "0.9", "openvpn": "2.5.11"},
	}}}
}

func TestSupportEndsSoonAndPast(t *testing.T) {
	until := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	m := sysinfo.Machine{OSName: "Ubuntu 22.04.5 LTS"}
	far := row(t, systemFacts(jammyReport(until), m, until.AddDate(-1, 0, 0)), "Поддержка выпуска")
	if far.Judged.Level() != ui.None || far.Value != "до 1 июня 2027" {
		t.Fatalf("за год до конца: %+v", far)
	}
	soon := row(t, systemFacts(jammyReport(until), m, until.AddDate(0, -2, 0)), "Поддержка выпуска")
	if soon.Judged.Level() != ui.Warn || !strings.Contains(soon.Note, "26.04") {
		t.Fatalf("за два месяца до конца: %+v", soon)
	}
	past := row(t, systemFacts(jammyReport(until), m, until.AddDate(0, 0, 1)), "Поддержка выпуска")
	if past.Judged.Level() != ui.Bad {
		t.Fatalf("после конца: %+v", past)
	}
}

func TestFactRowsSpeakHuman(t *testing.T) {
	f := systemFacts(jammyReport(time.Time{},
		hostcaps.Fact{ID: "nft.ruleset", Class: hostcaps.ClassGuard, Answer: hostcaps.No, Title: "Правила", Missing: "Обновите систему."},
		hostcaps.Fact{ID: "kea.socket_retry", Class: hostcaps.ClassFeature, Answer: hostcaps.No, Title: "Повтор", Missing: "Делать ничего не нужно."},
		hostcaps.Fact{ID: "kernel.cake", Class: hostcaps.ClassComfort, Answer: hostcaps.Unknown, Title: "Очередь"},
		hostcaps.Fact{ID: "os.codename", Class: hostcaps.ClassDecision, Answer: hostcaps.Yes, Value: "jammy", Title: "Выпуск"},
	), sysinfo.Machine{}, time.Now())
	if r := row(t, f, "Правила"); r.Judged.Level() != ui.Bad || r.Note != "Обновите систему." {
		t.Fatalf("защитное «нет»: %+v", r)
	}
	if r := row(t, f, "Повтор"); r.Judged.Level() != ui.None || r.Value != "нет" {
		t.Fatalf("необязательное «нет» не тревожит: %+v", r)
	}
	if r := row(t, f, "Очередь"); r.Value != "не удалось проверить" {
		t.Fatalf("неизвестно: %+v", r)
	}
	for _, it := range f.Items {
		if it.Label == "Выпуск" || it.Label == "os" || it.Label == "kernel" || strings.Contains(it.Label, ".") {
			t.Fatalf("сырая строка в блоке: %+v", it)
		}
	}
	if r := row(t, f, "openvpn"); r.Value != "2.5.11" {
		t.Fatalf("версия программы: %+v", r)
	}
}

func TestStaleSectionIsNamed(t *testing.T) {
	r := jammyReport(time.Time{})
	r.Stale = []settings.Section{settings.SectionDHCP}
	if got := row(t, systemFacts(r, sysinfo.Machine{}, time.Now()), "Настройки DHCP"); got.Judged.Level() != ui.Warn {
		t.Fatalf("неперерисованный раздел: %+v", got)
	}
}

func TestAgentDownSaysWhatToDo(t *testing.T) {
	f := systemFacts(system.Report{AgentDown: true}, sysinfo.Machine{OSName: "Ubuntu"}, time.Now())
	if r := row(t, f, "Проверка системы"); !strings.Contains(r.Note, "перезагрузите") {
		t.Fatalf("служба молчит: %+v", r)
	}
}

func TestHomeNoticesOnlyForGuardAndStale(t *testing.T) {
	r := jammyReport(time.Time{},
		hostcaps.Fact{ID: "nft.ruleset", Class: hostcaps.ClassGuard, Answer: hostcaps.No, Missing: "Обновите систему."},
		hostcaps.Fact{ID: "kernel.cake", Class: hostcaps.ClassComfort, Answer: hostcaps.No, Missing: "QoS недоступен."},
		hostcaps.Fact{ID: "kernel.tun", Class: hostcaps.ClassGuard, Answer: hostcaps.Unknown},
	)
	r.Stale = []settings.Section{settings.SectionDHCP}
	n := systemNotices(r)
	if len(n) != 2 || n[0].Level != "error" || n[0].Text != "Обновите систему." || n[1].Level != "warn" {
		t.Fatalf("плашки главной: %+v", n)
	}
}

func TestTakeoverFactRow(t *testing.T) {
	if _, ok := takeoverFactRow(system.TakeoverPlan{State: "none"}, nil); ok {
		t.Fatal("строка без захвата")
	}
	if _, ok := takeoverFactRow(system.TakeoverPlan{State: "done"}, errors.New("агент")); ok {
		t.Fatal("строка при ошибке агента")
	}
	cases := map[string]string{"window": "остановлен", "finishing": "выключается", "partial": "часть не выключилась", "done": "выключен"}
	for state, want := range cases {
		row, ok := takeoverFactRow(system.TakeoverPlan{State: state, Failed: 2, Backup: "/var/backups/vpn-panel/takeover-x", Residue: []string{"resolved_header"}}, nil)
		if !ok || !strings.Contains(row.Value, want) {
			t.Errorf("%s: %+v", state, row)
		}
		if state == "partial" && (row.Judged.Level() != ui.Warn || !strings.Contains(row.Note, "Не удалось 2")) {
			t.Errorf("частичная неудача без предупреждения: %+v", row)
		}
		if state == "done" && (!strings.Contains(row.Note, "takeover-x") || !strings.Contains(row.Note, "Следы")) {
			t.Errorf("итог без копии или остатков: %+v", row)
		}
	}
}
