package reliability

import (
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

const SeenEvery = 5 * time.Minute

const (
	CodePanelCrashed    = "panel_crashed"
	CodeUncleanShutdown = "unclean_shutdown"
)

type Verdict struct {
	Code    string
	Details string
}

func Judge(cur, last *models.Boot) Verdict {
	stamp := func(t time.Time) string { return t.Local().Format("02.01.2006 15:04:05") }
	switch {
	case cur != nil && !cur.CleanStop:
		return Verdict{Code: CodePanelCrashed,
			Details: "панель остановилась, не завершив работу, и запущена снова; последний признак жизни — " + stamp(cur.SeenAt)}
	case cur == nil && last != nil && !last.CleanStop:
		return Verdict{Code: CodeUncleanShutdown,
			Details: "загрузка сервера с " + stamp(last.BootedAt) + " закончилась без штатной остановки панели: пропадало питание, сервер завис, его выключили кнопкой или панель перед этим не работала; последний признак жизни — " + stamp(last.SeenAt)}
	}
	return Verdict{}
}

type Runner struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
	id   uint
}

func NewRunner() *Runner { return &Runner{stop: make(chan struct{}), done: make(chan struct{})} }

func (r *Runner) Signature() string { return "vpn-panel:boots" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	r.id = start(time.Now())
	tick := time.NewTicker(SeenEvery)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			r.mark(time.Now(), true)
			return nil
		case <-tick.C:
			r.mark(time.Now(), false)
		}
	}
}

func (r *Runner) Shutdown() error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
		log.Printf("журнал запусков: остановка не дождалась отметки")
	}
	return nil
}

func (r *Runner) mark(now time.Time, clean bool) {
	if r.id == 0 {
		return
	}
	upd := map[string]any{"seen_at": now}
	if clean {
		upd["clean_stop"] = true
	}
	if _, err := facades.Orm().Query().Model(&models.Boot{}).Where("id", r.id).Update(upd); err != nil {
		log.Printf("журнал запусков: отметка не записана: %v", err)
	}
}

func start(now time.Time) uint {
	bootID, ok := sysinfo.BootID()
	boot, bootOK := sysinfo.Uptime()
	if !ok || !bootOK {
		log.Printf("журнал запусков: ядро не сообщило идентификатор или время загрузки — перезагрузки не считаются")
		return 0
	}
	var cur, last models.Boot
	q := facades.Orm().Query()
	if err := q.Where("boot_id", bootID).First(&cur); err != nil {
		log.Printf("журнал запусков: чтение: %v", err)
		return 0
	}
	var curPtr, lastPtr *models.Boot
	if cur.ID != 0 {
		curPtr = &cur
	} else if err := facades.Orm().Query().OrderBy("id", "desc").First(&last); err == nil && last.ID != 0 {
		lastPtr = &last
	}
	if v := Judge(curPtr, lastPtr); v.Code != "" {
		securitylog.Record(models.AuthEvent{Event: v.Code, Details: v.Details, OccurredAt: now})
	}
	if curPtr != nil {
		if _, err := facades.Orm().Query().Model(&models.Boot{}).Where("id", cur.ID).Update(map[string]any{
			"last_start_at": now, "seen_at": now, "clean_stop": false, "panel_starts": cur.PanelStarts + 1,
		}); err != nil {
			log.Printf("журнал запусков: запись: %v", err)
			return 0
		}
		return cur.ID
	}

	if lastPtr == nil {
		noteFirstStart(now)
	}
	row := models.Boot{BootID: bootID, BootedAt: boot.Since, FirstStartAt: now, LastStartAt: now, SeenAt: now, PanelStarts: 1}
	if err := facades.Orm().Query().Create(&row); err != nil {
		log.Printf("журнал запусков: запись: %v", err)
		return 0
	}
	return row.ID
}
