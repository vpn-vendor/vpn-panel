package controllers

import (
	"sort"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/listen"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const ownerSurroundings = "проверка обстановки самим шлюзом"

func surroundOrder(id string) int {
	switch {
	case id == "legacy.gateway":
		return 0
	case strings.HasPrefix(id, "legacy.danger."), id == "surroundings.forward_boot", officeBreak(id):
		return 1
	case strings.HasPrefix(id, "legacy."):
		return 2
	}
	return 3
}

func judgeLevel(level string) ui.Judgment {
	switch level {
	case hostcaps.LevelError:
		return ui.Judge(ui.Bad, ownerSurroundings)
	case hostcaps.LevelWarn:
		return ui.Judge(ui.Warn, ownerSurroundings)
	}
	return ui.Judgment{}
}

func foundValue(f hostcaps.Fact) string {
	switch f.ID {
	case "legacy.gateway":
		if m := legacyvpn.ModeWord(f.Value); m != "" {
			return m
		}
	case "legacy.running":
		if f.Value == "changing" {
			return "меняет систему"
		}
		return "ждёт ответа в консоли"
	}
	if f.Value != "" {
		return f.Value
	}
	return "найдено"
}

func surroundFacts(st hostcaps.Surroundings, down bool, now time.Time) ui.Facts {
	out := ui.Facts{Title: "Чужое на сервере"}
	switch {
	case down:
		out.Items = append(out.Items, ui.Fact{Label: "Проверка",
			Note: "Системная служба не ответила. Если это повторяется — перезагрузите сервер"})
		return out
	case st.Settling && len(st.Facts) == 0:
		out.Items = append(out.Items, ui.Fact{Label: "Проверка", Value: "идёт",
			Note: "Шлюз проверяет, что ещё работает на сервере. Обновите страницу через минуту"})
		return out
	}
	facts := append([]hostcaps.Fact(nil), st.Facts...)
	sort.SliceStable(facts, func(a, b int) bool { return surroundOrder(facts[a].ID) < surroundOrder(facts[b].ID) })
	clean := 0
	for _, f := range facts {
		switch f.Answer {
		case hostcaps.Yes:
			out.Items = append(out.Items, ui.Fact{Label: f.Title, Value: foundValue(f), Note: f.Found,
				Judged: judgeLevel(f.Level)})
		case hostcaps.Unknown:

			note := f.Found
			if note == "" {
				note = "Шлюз проверит снова через минуту"
			}
			out.Items = append(out.Items, ui.Fact{Label: f.Title, Value: "не удалось проверить", Note: note})
		default:
			clean++
		}
	}
	if clean > 0 {
		out.Items = append(out.Items, ui.Fact{Label: "Остальное", Value: "не найдено",
			Note: "Остальные проверки шлюза ничего не нашли"})
	}
	row := ui.Fact{Label: "Проверено", Value: st.TakenAt, Note: "Шлюз проверяет это каждую минуту"}
	if t, err := time.Parse(time.RFC3339, st.TakenAt); err == nil {
		row.Value = t.Local().Format("02.01.2006 15:04")
	}
	if st.Settling {
		row.Value, row.Note = "идёт", "Шлюз перепроверяет найденное после перезагрузки"
	}
	out.Items = append(out.Items, row)
	return out
}

func officeBreak(id string) bool {
	switch id {
	case "surroundings.forward_cut", "surroundings.forward_off", "surroundings.own_table":
		return true
	}
	return false
}

func surroundNotices(st hostcaps.Surroundings) []notice {
	var out, cut []notice
	var legacy, danger []hostcaps.Fact
	for _, f := range st.Facts {
		if f.Answer != hostcaps.Yes {
			continue
		}
		switch {
		case strings.HasPrefix(f.ID, "legacy.danger."), f.ID == "surroundings.forward_boot":
			danger = append(danger, f)
		case (f.ID == "surroundings.forward_cut" || f.ID == "surroundings.forward_off") && f.Level == hostcaps.LevelError:
			cut = append(cut, notice{Level: "error", Text: f.Found, ActionURL: "/diagnostics", ActionText: "Открыть диагностику"})
		case f.ID == "surroundings.forward_off", f.ID == "surroundings.dhcp_lan", f.ID == "surroundings.own_table":

			if f.Level == hostcaps.LevelError || f.Level == hostcaps.LevelWarn {
				out = append(out, notice{Level: noticeLevel(f.Level), Text: f.Found,
					ActionURL: "/diagnostics", ActionText: "Открыть диагностику"})
			}
		case f.Cause == hostcaps.CauseLegacy:
			legacy = append(legacy, f)
		case f.ID == "surroundings.tls_port":

		case f.Level == hostcaps.LevelError || f.Level == hostcaps.LevelWarn:
			out = append(out, notice{Level: noticeLevel(f.Level), Text: f.Found,
				ActionURL: "/diagnostics", ActionText: "Открыть диагностику"})
		}
	}
	if len(legacy) > 0 {
		level, text := hostcaps.LevelInfo, legacy[0].Found
		for _, f := range legacy {
			if f.ID == "legacy.gateway" {
				text = f.Found
			}
			if rank(f.Level) > rank(level) {
				level = f.Level
			}
		}
		if len(legacy) > 1 {
			text += " Ещё " + ui.Plural(len(legacy)-1, "находка", "находки", "находок") + " от старого скрипта — подробности в «Диагностике»."
		}
		out = append([]notice{{Level: noticeLevel(level), Text: text, ActionURL: "/diagnostics", ActionText: "Открыть диагностику"}}, out...)
	}
	out = append(cut, out...)
	if len(danger) > 0 {
		titles := make([]string, 0, len(danger))
		for _, f := range danger {
			titles = append(titles, lowerFirst(f.Title))
		}
		text := "На сервере найдены опасные настройки: " + strings.Join(titles, ", ") + ". Что делать с каждой — в «Диагностике»."
		if len(danger) == 1 {
			text = danger[0].Found
		}
		out = append([]notice{{Level: "error", Text: text, ActionURL: "/diagnostics", ActionText: "Открыть диагностику"}}, out...)
	}
	return out
}

func rank(level string) int {
	switch level {
	case hostcaps.LevelError:
		return 2
	case hostcaps.LevelWarn:
		return 1
	}
	return 0
}

func noticeLevel(level string) string {
	switch level {
	case hostcaps.LevelError:
		return "error"
	case hostcaps.LevelWarn:
		return "warn"
	}
	return "info"
}

func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToLower(string(r[0])) + string(r[1:])
}

func providerNotes(st hostcaps.Surroundings, rolesApplied bool) []notice {
	level := func(f hostcaps.Fact) string {
		if rolesApplied {
			return noticeLevel(f.Level)
		}
		return "warn"
	}
	var out []notice
	if st.Settling {
		n := notice{Level: "warn", Text: "Шлюз ещё проверяет, что работает на сервере. Если на нём стоит старый скрипт vpn.sh, это станет видно через минуту."}
		if rolesApplied {
			n.Level = "info"
		}
		out = append(out, n)
	}
	ids := []string{"legacy.gateway", "legacy.running"}
	if !rolesApplied {
		ids = append(ids, "surroundings.forward_cut")
	}
	for _, id := range ids {
		if f, ok := st.Fact(id); ok && f.Answer == hostcaps.Yes && f.Found != "" {
			out = append(out, notice{Level: level(f), Text: f.Found})
		}
	}
	return out
}

func networkNotices(st hostcaps.Surroundings, rolesApplied bool) []notice {
	var out []notice
	for _, n := range providerNotes(st, rolesApplied) {
		if n.Level != "info" {
			out = append(out, n)
		}
	}
	return out
}

const httpBusyAfter = 2 * time.Minute

func withOwnBinding(st hostcaps.Surroundings, inUse map[string]time.Time, now time.Time) hostcaps.Surroundings {
	lan, local, young := false, false, false
	for addr, since := range inUse {
		switch {
		case now.Sub(since) < httpBusyAfter:
			young = true
		case addr == "127.0.0.1":
			local = true
		default:
			lan = true
		}
	}
	facts := append([]hostcaps.Fact(nil), st.Facts...)
	for i, f := range facts {
		if f.ID != "surroundings.http_port" || f.Answer != hostcaps.Yes || lan {
			continue
		}
		f.Level = hostcaps.LevelInfo
		switch {
		case young:

		case local:
			f.Found = "Порт 80 на самом сервере занят программой " + f.Value + ": в браузере на сервере открывайте панель по адресу с https://. С компьютеров офиса короткий адрес работает."
		default:
			f.Found = "Программа " + f.Value + " слушает порт 80 на другом адресе сервера. Панели это не мешает."
		}
		facts[i] = f
	}
	st.Facts = facts
	return st
}

func panelInUse() map[string]time.Time {
	if m := listen.Current(); m != nil {
		return m.Snapshot().RedirectInUse
	}
	return nil
}

func holdSeen(st hostcaps.Surroundings, seen map[string]system.SeenFact) hostcaps.Surroundings {
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	facts := append([]hostcaps.Fact(nil), st.Facts...)
	at := map[string]int{}
	for i, f := range facts {
		at[f.ID] = i
	}
	for _, id := range ids {
		f := seen[id]
		if f.Answer != string(hostcaps.Yes) || f.Found == "" {
			continue
		}
		note := "Шлюз перепроверяет это"
		if t, err := time.Parse(time.RFC3339, f.At); err == nil {
			note = "Замечено " + t.Local().Format("02.01.2006 15:04") + "; шлюз перепроверяет это"
		}
		held := hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: hostcaps.Yes,
			Level: f.Level, Cause: f.Cause, Title: f.Title, Value: f.Value}
		i, published := at[id]
		switch {

		case published && facts[i].Answer == hostcaps.Unknown && !facts[i].Reset:
			held.Found = f.Found + " " + note + "."
			if why := facts[i].Found; why != "" {
				held.Found += " " + why
			}
			facts[i] = held
		case !published && st.Settling:
			held.Found = f.Found + " " + note + " после перезагрузки."
			facts = append(facts, held)
		}
	}
	st.Facts = facts
	return st
}
