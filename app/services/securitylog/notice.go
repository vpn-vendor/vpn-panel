package securitylog

import (
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

const NoticeFor = 7 * 24 * time.Hour

const noticeFresh = time.Minute

type UnattendedNotice struct {
	At   time.Time
	Text string
}

var noticeCache struct {
	mu  sync.Mutex
	at  time.Time
	out []UnattendedNotice
}

func NoticeCodes() []string { return Codes(func(e Entry) bool { return e.Notice != "" }) }

func Unattended(now time.Time) []UnattendedNotice {
	noticeCache.mu.Lock()
	defer noticeCache.mu.Unlock()
	if !noticeCache.at.IsZero() && now.Sub(noticeCache.at) >= 0 && now.Sub(noticeCache.at) < noticeFresh {
		return noticeCache.out
	}
	var out []UnattendedNotice
	for _, code := range NoticeCodes() {
		var row models.AuthEvent
		err := facades.Orm().Query().Where("event", code).Where("occurred_at >= ?", now.Add(-NoticeFor)).
			OrderByDesc("occurred_at").First(&row)
		if err != nil || row.ID == 0 {
			continue
		}
		e, _ := Lookup(code)
		out = append(out, UnattendedNotice{At: row.OccurredAt, Text: e.Notice})
	}
	noticeCache.at, noticeCache.out = now, out
	return out
}

func forgetNotices(code string) {
	if e, ok := Lookup(code); !ok || e.Notice == "" {
		return
	}
	noticeCache.mu.Lock()
	noticeCache.at = time.Time{}
	noticeCache.mu.Unlock()
}
