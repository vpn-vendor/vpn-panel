package retention

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
)

type Runner struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRunner() *Runner { return &Runner{stop: make(chan struct{}), done: make(chan struct{})} }

func (r *Runner) Signature() string { return "vpn-panel:retention" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	tick := time.NewTicker(DiskCheckEvery)
	defer tick.Stop()
	perSweep := int(SweepEvery / DiskCheckEvery)
	n := 0
	DiskCheck(time.Now(), nil)
	for {
		select {
		case <-r.stop:
			securitylog.FlushAll()
			return nil
		case <-first.C:
			Sweep(time.Now())
		case <-tick.C:
			now := time.Now()
			DiskCheck(now, trimViaAgent)
			if n++; n%perSweep == 0 {
				Sweep(now)
			}
		}
	}
}

func (r *Runner) Shutdown() error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
		log.Printf("уборка: остановка не дождалась сброса журнала")
	}
	return nil
}

var sweepHooks []func()

func OnSweep(fn func()) { sweepHooks = append(sweepHooks, fn) }

type sweepPart struct {
	name string
	fn   func() (int, error)
}

func Sweep(now time.Time) {
	securitylog.Flush(now)
	for _, fn := range sweepHooks {
		fn()
	}
	st := Load()
	ordinary := anySlice(securitylog.CodesOf(securitylog.Ordinary))
	system := anySlice(securitylog.CodesOf(securitylog.System))
	notCritical := append(append([]any{}, ordinary...), system...)

	journalDays, ordinaryCap, systemCap := st.JournalDays, OrdinaryCap, securitylog.SystemCap(SystemKeepDays)
	if d := CurrentDisk(); d.OverBudget() || d.Starved {
		journalDays, ordinaryCap, systemCap = JournalDaysMin, OrdinaryCapTight, securitylog.SystemCap(SystemKeepDaysTight)
	}

	parts := []sweepPart{
		{"журнал безопасности: срок", func() (int, error) {
			return deleteIDs(&models.AuthEvent{}, events().
				Where("occurred_at < ?", now.AddDate(0, 0, -journalDays)), Batch)
		}},
		{"журнал безопасности: потолок обычных", func() (int, error) {
			return trimToCap(func() orm.Query { return events().WhereIn("event", ordinary) }, ordinaryCap)
		}},
		{"журнал безопасности: потолок системных", func() (int, error) {
			return trimToCap(func() orm.Query { return events().WhereIn("event", system) }, systemCap)
		}},
		{"журнал безопасности: потолок критичных", func() (int, error) {
			return trimToCap(func() orm.Query { return events().Where("event NOT IN ?", notCritical) }, CriticalCap)
		}},
		{"журнал запусков: срок", func() (int, error) {
			return deleteIDs(&models.Boot{}, facades.Orm().Query().Model(&models.Boot{}).
				Where("booted_at < ? AND id < (SELECT MAX(id) FROM boots)", now.AddDate(0, 0, -BootsKeepDays)), Batch)
		}},
		{"устройства: забывание", func() (int, error) {
			return forgetDevices(now.AddDate(0, 0, -st.ForgetDays))
		}},
		{"коды подключения", func() (int, error) {
			return deleteIDs(&models.EnrollCode{}, facades.Orm().Query().Model(&models.EnrollCode{}).
				Where("expires_at < ?", now.AddDate(0, 0, -CodesKeepDays)), Batch)
		}},
		{"следы мёртвых доверий устройств", func() (int, error) {
			n, err := auth.New().PurgeDead(now.AddDate(0, 0, -st.TrustDays), Batch)
			if err == nil && n == 0 {
				err = errNothing
			}
			return n, err
		}},
	}
	runParts(parts, now.Add(SweepBudget), time.Now)
}

func runParts(parts []sweepPart, deadline time.Time, clock func() time.Time) {
	for _, p := range parts {
		for clock().Before(deadline) {
			n, err := p.fn()
			if err != nil && !errors.Is(err, errNothing) {
				log.Printf("уборка данных (%s): %v", p.name, err)
			}
			if err != nil || n < Batch {
				break
			}
		}
	}
}

func events() orm.Query { return facades.Orm().Query().Model(&models.AuthEvent{}) }

func deleteIDs(model any, q orm.Query, limit int) (int, error) {
	var ids []uint
	if err := q.OrderBy("id").Limit(limit).Pluck("id", &ids); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, errNothing
	}
	if _, err := facades.Orm().Query().WhereIn("id", uintsToAny(ids)).Delete(model); err != nil {
		return 0, err
	}
	return len(ids), nil
}

func trimToCap(base func() orm.Query, ceiling int) (int, error) {
	n, err := base().Count()
	if err != nil {
		return 0, err
	}
	excess := int(n) - ceiling
	if excess <= 0 {
		return 0, errNothing
	}
	if excess > Batch {
		excess = Batch
	}
	return deleteIDs(&models.AuthEvent{}, base(), excess)
}

func forgetDevices(cutoff time.Time) (int, error) {
	var rows []models.Device
	err := facades.Orm().Query().
		Where("label = ? AND location = ? AND owner = ? AND note = ? AND label_source = ? AND proposed_at IS NULL AND last_seen_at < ?",
			"", "", "", "", "", cutoff).
		Where("lower(substr(mac, 2, 1)) IN ?", []string{"2", "6", "a", "e"}).
		OrderBy("id").Limit(Batch).Find(&rows)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNothing
	}
	var ids []any
	for _, r := range rows {
		if Forgettable(r, cutoff) {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) > 0 {
		if _, err := facades.Orm().Query().WhereIn("id", ids).Delete(&models.Device{}); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

func uintsToAny(ids []uint) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

func anySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
