package controllers

import (
	"fmt"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
)

const (
	devicesJudgeOwner = "раздел «Устройства»"
	journalJudgeOwner = "каталог журнала безопасности"
)

func devicesTag(text string, level ui.Level) ui.Tag {
	return ui.Tag{Text: text, Judged: ui.Judge(level, devicesJudgeOwner)}
}

func deviceKind(ua string) (icon, os string) {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "ipad"):
		return "tablet", "iPadOS"
	case strings.Contains(u, "iphone"):
		return "phone", "iOS"
	case strings.Contains(u, "android"):
		if strings.Contains(u, "mobile") {
			return "phone", "Android"
		}
		return "tablet", "Android"
	case strings.Contains(u, "windows"):
		return "laptop", "Windows"
	case strings.Contains(u, "mac os") || strings.Contains(u, "macintosh"):
		return "laptop", "macOS"
	case strings.Contains(u, "cros"):
		return "laptop", "ChromeOS"
	case strings.Contains(u, "linux"):
		return "desktop", "Linux"
	}
	return "desktop", ""
}

func deviceCards(views []deviceView, csrf string) ui.ItemGrid {
	grid := ui.ItemGrid{List: true}
	for _, d := range views {
		card := ui.ItemCard{Icon: d.Icon, Title: d.Label, Muted: d.Revoked, Current: d.Current}
		if card.Icon == "" {
			card.Icon = "desktop"
		}
		if d.Current {
			card.Tags = append(card.Tags, devicesTag("это устройство", ui.None))
		}
		if d.Main {
			card.Tags = append(card.Tags, devicesTag("главное", ui.OK))
		}
		if d.OS != "" {
			card.Tags = append(card.Tags, devicesTag(d.OS, ui.None))
		}
		switch {
		case d.Revoked:
			card.Tags = append(card.Tags, devicesTag("доступ отозван", ui.Warn))
		case d.Quarantine:
			card.Tags = append(card.Tags, devicesTag("добавлено недавно", ui.Warn))
			card.Note = "Первые часы оно не может приглашать другие устройства и отзывать доступ."
		}
		card.Meta = []string{d.LastIP, "последний вход " + d.LastUsed, "добавлено " + d.Created}
		if d.Current {
			card.Actions = append(card.Actions, ui.ActionForm{Action: "/logout", CSRF: csrf,
				Button: ui.Button{Label: "Выйти", Kind: "secondary", Small: true}})
		} else if !d.Revoked {
			card.Actions = append(card.Actions, ui.ActionForm{Action: "/devices/revoke", CSRF: csrf,
				Hidden: map[string]string{"device_id": fmt.Sprint(d.ID)},
				Button: ui.Button{Label: "Отозвать", Kind: "danger-outline", Small: true}})
		}
		grid.Items = append(grid.Items, card)
	}
	return grid
}

const (
	kindAccess   = "access"
	kindDeny     = "deny"
	kindSettings = "settings"
	kindSystem   = "system"
)

var denyCodes = map[string]bool{"code_failed": true, "setup_denied": true,
	"devices_new_throttled": true, "device_label_throttled": true}

var accessCodes = map[string]bool{"code_issued": true, "setup_code_issued": true, "setup_completed": true,
	"device_enrolled": true, "device_revoked": true, "device_signed_out": true, "devices_signed_out": true,
	"devices_reset": true, "device_new_ip": true}

func journalKind(code string) (string, ui.Tag) {
	e, ok := securitylog.Lookup(code)
	tag := func(text string, l ui.Level) ui.Tag {
		return ui.Tag{Text: text, Judged: ui.Judge(l, journalJudgeOwner)}
	}
	switch {
	case (ok && e.Failure) || denyCodes[code]:
		return kindDeny, tag("отказ", ui.Bad)
	case accessCodes[code]:
		return kindAccess, tag("доступ", ui.None)
	case ok && e.Class == securitylog.System, code == "panel_upgraded":
		return kindSystem, tag("система", ui.None)
	}
	return kindSettings, tag("настройки", ui.Warn)
}

func journalLevel(kind, code string) ui.Judgment {
	switch kind {
	case kindDeny:
		return ui.Judge(ui.Bad, journalJudgeOwner)
	case kindSettings:
		return ui.Judge(ui.Warn, journalJudgeOwner)
	}
	if e, ok := securitylog.Lookup(code); ok && e.Alarm {
		return ui.Judge(ui.Warn, journalJudgeOwner)
	}
	return ui.Judge(ui.OK, journalJudgeOwner)
}

func dayTitle(t, now time.Time) string {
	y, m, d := t.Date()
	ny, nm, nd := now.Date()
	switch {
	case y == ny && m == nm && d == nd:
		return "Сегодня"
	case y == ny && m == nm && d == nd-1:
		return "Вчера"
	}
	months := [...]string{"января", "февраля", "марта", "апреля", "мая", "июня",
		"июля", "августа", "сентября", "октября", "ноября", "декабря"}
	if y != ny {
		return fmt.Sprintf("%d %s %d", d, months[m-1], y)
	}
	return fmt.Sprintf("%d %s", d, months[m-1])
}

func journalTimeline(events []models.AuthEvent, now time.Time) ui.Timeline {
	tl := ui.Timeline{ID: "journal", Empty: "Событий пока нет: журнал начнётся с первого входа.",
		Filters: []ui.TimelineFilter{{Label: "Всё"}, {Kind: kindAccess, Label: "Доступ"}, {Kind: kindDeny, Label: "Отказы"},
			{Kind: kindSettings, Label: "Настройки"}, {Kind: kindSystem, Label: "Система"}}}
	var day *ui.TimelineDay
	for _, e := range events {
		local := e.OccurredAt.Local()
		title := dayTitle(local, now)
		if day == nil || day.Title != title {
			tl.Days = append(tl.Days, ui.TimelineDay{Title: title})
			day = &tl.Days[len(tl.Days)-1]
		}
		text := e.Details
		if e.IP != "" {
			if text != "" {
				text += " · "
			}
			text += "адрес " + e.IP
		}
		kind, tag := journalKind(e.Event)
		day.Events = append(day.Events, ui.TimelineEvent{
			Kind:   kind,
			Tag:    tag,
			Time:   local.Format("15:04"),
			Title:  eventTitle(e.Event),
			Text:   text,
			Extra:  repeatsText(e.RepeatCount, e.LastAt),
			Judged: journalLevel(kind, e.Event),
		})
	}
	return tl
}
