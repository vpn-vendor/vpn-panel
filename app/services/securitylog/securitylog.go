package securitylog

import (
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

const (
	DedupWindow = 60 * time.Second

	DedupKeys = 1024
)

var (
	mu    sync.Mutex
	dedup = NewDeduper(DedupWindow, DedupKeys)
)

func Record(e models.AuthEvent) {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	if ClassOf(e.Event) == Critical {
		insert(&e)
		forgetNotices(e.Event)
		return
	}
	now := e.OccurredAt
	mu.Lock()
	flushes := dedup.Expire(now)
	k := dedup.Resolve(Key{Event: e.Event, IP: e.IP})
	if dedup.Coalesce(k, now) {
		mu.Unlock()
		apply(flushes)
		return
	}
	mu.Unlock()
	apply(flushes)
	if !insert(&e) {
		return
	}
	mu.Lock()
	dedup.Open(k, e.ID, now)
	mu.Unlock()
}

func Flush(now time.Time) {
	mu.Lock()
	flushes := dedup.Expire(now)
	mu.Unlock()
	apply(flushes)
}

func FlushAll() {
	mu.Lock()
	flushes := dedup.All()
	mu.Unlock()
	apply(flushes)
}

func insert(e *models.AuthEvent) bool {
	if err := facades.Orm().Query().Create(e); err != nil {
		log.Printf("журнал безопасности: событие %s не записано: %v", e.Event, err)
		return false
	}
	return true
}

func apply(flushes []Pending) {
	for _, f := range flushes {

		if _, err := facades.Orm().Query().Model(&models.AuthEvent{}).Where("id", f.ID).
			Update(map[string]any{"repeat_count": f.Extra, "last_at": f.Last}); err != nil {
			log.Printf("журнал безопасности: повторы не дописаны: %v", err)
		}
	}
}
