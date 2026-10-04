package security

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const LeakCheckEvery = 30 * time.Second

const LeakNoticeFor = 7 * 24 * time.Hour

const SettingLeakSeen = "security.leak_seen"

func leakDelta(prev int64, known bool, cur int64, watched bool) (delta, next int64, nextKnown bool) {
	switch {
	case !watched:
		return 0, 0, false
	case !known || cur < prev:
		return cur, cur, true
	default:
		return cur - prev, cur, true
	}
}

func intentLost(was, now bool) bool { return now && !was }

type LeakRunner struct {
	s     *Service
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
	prev  int64
	known bool

	intent bool
}

func NewLeakRunner() *LeakRunner {
	return &LeakRunner{s: New(), stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *LeakRunner) Signature() string { return "vpn-panel:leakwatch" }
func (r *LeakRunner) ShouldRun() bool   { return true }

func (r *LeakRunner) Run() error {
	defer close(r.done)
	tick := time.NewTicker(LeakCheckEvery)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return nil
		case <-tick.C:
			r.check(time.Now())
		}
	}
}

func (r *LeakRunner) Shutdown() error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (r *LeakRunner) check(now time.Time) {
	st, err := r.s.Status()
	if err != nil {
		return
	}
	if intentLost(r.intent, st.IntentBroken) {
		securitylog.Record(models.AuthEvent{Event: "vpn_intent_broken", OccurredAt: now,
			Details: "настройки защищённого канала не читаются — офис закрыт от интернета до выбора режима администратором"})
	}
	r.intent = st.IntentBroken
	var delta int64
	delta, r.prev, r.known = leakDelta(r.prev, r.known, st.LeakedOutbound, st.LeakWatch)
	if delta <= 0 {
		return
	}
	securitylog.Record(models.AuthEvent{Event: "vpn_leak_detected", OccurredAt: now,
		Details: fmt.Sprintf("мимо защищённого канала к провайдеру ушло пакетов: %d", delta)})
	_ = settings.Set(SettingLeakSeen, strconv.FormatInt(now.Unix(), 10)+" "+strconv.FormatInt(delta, 10))
}

func LeakNotice(now time.Time) string {
	return leakNoticeText(settings.Get(SettingLeakSeen), now)
}

func leakNoticeText(raw string, now time.Time) string {
	stamp, count, ok := strings.Cut(raw, " ")
	if !ok {
		return ""
	}
	sec, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return ""
	}
	at := time.Unix(sec, 0)
	if now.Sub(at) > LeakNoticeFor {
		return ""
	}
	return "Защита зафиксировала утечку " + at.Local().Format("02.01.2006 15:04") +
		": пакетов — " + count + ", они ушли к провайдеру в обход защищённого канала. " +
		"Это сбой защиты, а не настройка: не выключайте защищённый режим и сообщите в поддержку. " +
		"Подробности — в журнале безопасности на странице «Устройства»."
}
