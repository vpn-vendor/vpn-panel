package controllers

import (
	"strconv"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

const (
	ownerDrops    = "определение обрыва мониторингом пути"
	ownerFailures = "каталог отказов журнала безопасности"
	ownerBoots    = "журнал запусков"
)

func historyLevel(n int, full bool, owner string) ui.Judgment {
	switch {
	case n > 0:
		return ui.Judge(ui.Warn, owner)
	case full:
		return ui.Judge(ui.OK, owner)
	}
	return ui.Judgment{}
}

func tunnelLiveUp(f overviewFacts) bool {
	if f.CollectOff {
		return false
	}
	for _, p := range f.Paths {
		if p.Kind == pathmon.Tunnel && p.State == pathprobe.Up {
			return true
		}
	}
	return false
}

func reliabilityFacts(f overviewFacts) ui.Facts {
	s := f.Reliability
	out := ui.Facts{Title: "Надёжность"}
	if s.Observed.IsZero() {
		out.Items = []ui.Fact{{Label: "Наблюдение", Note: "Журнал запусков панели ещё не записан: счётчики появятся после первого запуска службы."}}
		return out
	}
	stamp := func(t time.Time) string { return t.Local().Format("02.01.2006 15:04") }
	full := !s.Observed.After(s.Now.Add(-reliability.Week))
	if !full {

		out.Items = append(out.Items, ui.Fact{Label: "Наблюдение", Value: "с " + stamp(s.Observed),
			Note: "Панель считает с момента установки; полная неделя наберётся " + stamp(s.Observed.Add(reliability.Week))})
	}

	drops := ui.Fact{Label: "Обрывы VPN",
		Value:  strconv.Itoa(s.DropsDay) + " за сутки, " + strconv.Itoa(s.DropsWeek) + " за неделю",
		Note:   "Обрыв — сервер VPN не ответил пять проб подряд; каждый рвёт идущие разговоры. Частые обрывы разбираются в разделе VPN",
		Judged: historyLevel(s.DropsWeek, full, ownerDrops)}
	switch {
	case !f.Protected && !s.LongestOK && s.DropsWeek == 0:
		drops.Value, drops.Judged = "", ui.Judgment{}
		drops.Note = "VPN выключен: офис работает напрямую, обрывы канала не считаются"
	case f.CollectOff:
		drops.Note = "Сбор показателей выключен: новые обрывы сейчас не замечаются, показана история"
	}
	out.Items = append(out.Items, drops)

	longest := ui.Fact{Label: "Самый долгий отрезок без обрыва", Note: "VPN за неделю не наблюдался"}
	if s.LongestOK {
		longest.Value = humanSeconds(int64(s.Longest.Seconds()))
		longest.Note = "За неделю. Оценка осторожная: перезапуск панели и выключенный сбор показателей обрывают отрезок"
	}
	out.Items = append(out.Items, longest)

	reboots := ui.Fact{Label: "Перезагрузок сервера за неделю", Value: strconv.Itoa(s.RebootsWeek),
		Note: "Перезагрузки видны с момента установки панели", Judged: historyLevel(s.UncleanWeek, full, ownerBoots)}
	if f.BootOK {
		reboots.Note = "Последняя загрузка — " + stamp(f.Boot.Since)
	}
	if s.UncleanWeek > 0 {
		reboots.Note += "; без штатной остановки: " + strconv.Itoa(s.UncleanWeek) +
			" — пропадало питание или сервер зависал. Проверьте блок питания и ИБП"
	}
	out.Items = append(out.Items, reboots)

	out.Items = append(out.Items, ui.Fact{Label: "Отказов за сутки", Value: strconv.Itoa(s.FailuresDay),
		Note:   "Действия, которые шлюз не смог выполнить, и аварии панели; что именно — в журнале безопасности раздела «Устройства»",
		Judged: historyLevel(s.FailuresDay, full, ownerFailures)})
	return out
}
