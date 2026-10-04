package metrics

import (
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
)

type dbStore struct{}

func (dbStore) Get(key string) string { return settings.Get(key) }

func (dbStore) Set(key, value string) error { return settings.Set(key, value) }

type Runner struct {
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	dataDir string
	roles   func() Roles
	extra   []Source
}

func NewRunner(dataDir string, roles func() Roles, extra ...Source) *Runner {
	return &Runner{stop: make(chan struct{}), done: make(chan struct{}), dataDir: dataDir, roles: roles, extra: extra}
}

func (r *Runner) Signature() string { return "vpn-panel:metrics" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	links := NewLinkSource(r.roles, rtnl.Dump)
	lanName := func() string {
		if ls := r.roles().LANs; len(ls) > 0 {
			return ls[0]
		}
		return ""
	}
	qos := NewQoSSource(r.roles, rtnl.DumpQdiscs, rtnl.Dump)
	c := New(Sources(links, qos, r.extra...), dbStore{}, r.dataDir, lanName)
	c.Load()
	setCurrent(c)
	return r.loop(c, links)
}

func (r *Runner) loop(c *Collector, links *LinkSource) error {

	if w, err := rtnl.Watch(); err == nil {
		go func() {
			buf := make([]byte, 64<<10)
			for {
				evs, err := w.Next(buf)
				if err != nil {
					return
				}
				if len(evs) > 0 {
					links.Invalidate()
				}
			}
		}()
		defer func() { _ = w.Close() }()
	} else {
		log.Printf("сбор показателей: подписка на события карт недоступна (%v) — роли перечитываются по ошибке дампа", err)
	}
	tick := time.NewTicker(Tick)
	defer tick.Stop()
	save := time.NewTicker(SaveEvery)
	defer save.Stop()
	for {
		select {
		case <-r.stop:
			if err := c.Save(); err != nil {
				log.Printf("сбор показателей: сохранение при остановке: %v", err)
			}
			return nil
		case now := <-tick.C:
			c.Tick(now)
		case <-save.C:
			if err := c.Save(); err != nil {
				log.Printf("сбор показателей: сохранение: %v", err)
			}
		}
	}
}

func (r *Runner) Shutdown() error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
		log.Printf("сбор показателей: остановка не дождалась сохранения")
	}
	return nil
}
