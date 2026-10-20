package controllers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/oswindow"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

const (
	ownerHostCheck = "проверка системы самим шлюзом"
	ownerSupport   = "сроки поддержки выпусков Ubuntu"
)

const supportWarnAhead = 183 * 24 * time.Hour

var monthsGen = [...]string{"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря"}

func dateRU(t time.Time) string {
	return fmt.Sprintf("%d %s %d", t.Day(), monthsGen[t.Month()-1], t.Year())
}

const ownerTakeover = "выключение старого шлюза"

func takeoverFactRow(p system.TakeoverPlan, err error) (ui.Fact, bool) {
	if err != nil || p.State == "" || p.State == "none" {
		return ui.Fact{}, false
	}
	row := ui.Fact{Label: "Старый шлюз"}
	switch p.State {
	case "window":
		row.Value = "остановлен на время проверки сети"
		row.Note = "Выключится после подтверждения связи; если связи не будет, вернётся вместе с прежней сетью"
	case "finishing":
		row.Value = "выключается"
		row.Note = "Старые службы выключаются, их файлы уходят в резервную копию. Обновите страницу через минуту"
	case "partial":
		row.Value = "часть не выключилась"
		row.Judged = ui.Judge(ui.Warn, ownerTakeover)
		row.Note = fmt.Sprintf("Не удалось %d; шлюз повторяет сам при каждом запуске. Если строка держится дольше часа — соберите сведения для поддержки", p.Failed)
	case "done":
		row.Value = "выключен"
		row.Note = "Файлы старого шлюза лежат в резервной копии " + p.Backup
		if len(p.Residue) > 0 {
			row.Note += ". Следы старого скрипта на сервере остались, они не мешают"
		}
	default:
		return ui.Fact{}, false
	}
	return row, true
}

func systemFacts(r system.Report, m sysinfo.Machine, now time.Time) ui.Facts {
	out := ui.Facts{Title: "Система шлюза"}
	osRow := ui.Fact{Label: "Система", Value: m.OSName, Note: "Её называют, когда пишут в поддержку"}
	if r.Release.Codename == "" && !r.AgentDown && r.Status.TakenAt != "" {
		osRow.Judged = ui.Judge(ui.Warn, ownerHostCheck)
		osRow.Note = "Панель проверена только на Ubuntu " + supportedList() + ". На этой системе она может работать не полностью"
	}
	out.Items = append(out.Items, osRow)
	if !r.SupportUntil.IsZero() {
		out.Items = append(out.Items, releaseSupportRow(r, now))
	}
	if m.Kernel != "" {
		out.Items = append(out.Items, ui.Fact{Label: "Ядро", Value: m.Kernel, Note: "Модули ядра шлюз проверяет после каждого обновления"})
	}

	switch {
	case r.AgentDown:
		out.Items = append(out.Items, ui.Fact{Label: "Проверка системы",
			Note: "Системная служба не ответила. Если это повторяется — перезагрузите сервер"})
		return out
	case r.Status.TakenAt == "" || r.Status.Probing:
		out.Items = append(out.Items, ui.Fact{Label: "Проверка системы", Value: "идёт",
			Note: "Шлюз проверяет, что умеет эта система. Обновите страницу через минуту"})
		if r.Status.TakenAt == "" {
			return out
		}
	default:
		row := ui.Fact{Label: "Проверка системы", Value: r.Status.TakenAt,
			Note: "Шлюз проверяет систему после каждого обновления программ и рисует настройки по этой проверке"}
		if t, err := time.Parse(time.RFC3339, r.Status.TakenAt); err == nil {
			row.Value = t.Local().Format("02.01.2006 15:04")
		}
		out.Items = append(out.Items, row)
	}
	for _, sec := range r.Stale {
		out.Items = append(out.Items, ui.Fact{Label: "Настройки " + sec.Title(), Value: "не перерисованы",
			Judged: ui.Judge(ui.Warn, ownerHostCheck),
			Note:   "Программы системы обновились, а настройки раздела ещё не догнали их. Шлюз повторяет сам; если строка не уходит час — соберите сведения для поддержки"})
	}
	for _, f := range r.Status.Facts {
		if row, ok := factRow(f); ok {
			out.Items = append(out.Items, row)
		}
	}
	out.Items = append(out.Items, versionRows(r.Status.Versions)...)
	return out
}

func releaseSupportRow(r system.Report, now time.Time) ui.Fact {
	row := ui.Fact{Label: "Поддержка выпуска", Value: "до " + dateRU(r.SupportUntil),
		Note: "До этой даты Ubuntu выпускает исправления безопасности для этого выпуска"}
	next := "Новая версия панели подскажет, на какой выпуск переходить"
	if all := oswindow.Supported(); len(all) > 0 && all[len(all)-1].Codename != r.Release.Codename {
		next = "Обновите систему до Ubuntu " + all[len(all)-1].Version + " или поставьте шлюз с флешки"
	}
	switch left := r.SupportUntil.Sub(now); {
	case left <= 0:
		row.Value = "закончилась " + dateRU(r.SupportUntil)
		row.Judged = ui.Judge(ui.Bad, ownerSupport)
		row.Note = "Ubuntu больше не выпускает исправления безопасности для этой системы. " + next
	case left < supportWarnAhead:
		row.Judged = ui.Judge(ui.Warn, ownerSupport)
		row.Note = "Поддержка скоро закончится. " + next
	}
	return row
}

func factRow(f hostcaps.Fact) (ui.Fact, bool) {
	if f.Class == hostcaps.ClassDecision && f.Answer == hostcaps.Yes {
		return ui.Fact{}, false
	}
	title := f.Title
	if title == "" {
		title = "Возможность системы"
	}
	row := ui.Fact{Label: title}
	switch f.Answer {
	case hostcaps.Yes:
		row.Value = "есть"
	case hostcaps.No:
		row.Value, row.Note = "нет", f.Missing
		switch f.Class {
		case hostcaps.ClassGuard, hostcaps.ClassDecision:
			row.Judged = ui.Judge(ui.Bad, ownerHostCheck)
		case hostcaps.ClassComfort:
			row.Judged = ui.Judge(ui.Warn, ownerHostCheck)
		}
	default:
		row.Value = "не удалось проверить"
		row.Note = "Шлюз обходится без этого и проверит снова после обновления программ"
		if f.Class == hostcaps.ClassGuard {
			row.Judged = ui.Judge(ui.Warn, ownerHostCheck)
			row.Note = "Применение настроек проверит это само и откажет, если система не справится"
		}
	}
	return row, true
}

func versionRows(v map[string]string) []ui.Fact {
	names := make([]string, 0, len(v))
	for name := range v {
		switch name {
		case "os", "kernel", "vpn-panel":
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]ui.Fact, 0, len(names))
	for _, name := range names {
		rows = append(rows, ui.Fact{Label: name, Value: v[name]})
	}
	return rows
}

func supportedList() string {
	var vs []string
	for _, r := range oswindow.Supported() {
		vs = append(vs, r.Version)
	}
	return strings.Join(vs, " и ")
}

func systemNotices(r system.Report) []notice {
	var out []notice
	for _, f := range r.Status.Facts {
		if f.Class == hostcaps.ClassGuard && f.Answer == hostcaps.No {
			out = append(out, notice{Level: "error", Text: f.Missing,
				ActionURL: "/diagnostics", ActionText: "Открыть диагностику"})
		}
	}
	for _, sec := range r.Stale {
		out = append(out, notice{Level: "warn",
			Text:      "Программы системы обновились, а настройки раздела «" + sec.Title() + "» ещё не перерисованы под них. Шлюз повторяет сам.",
			ActionURL: "/diagnostics", ActionText: "Открыть диагностику"})
	}
	return out
}
