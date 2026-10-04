package restore

import (
	"log"
	"sync"
	"time"
)

const checkShare = 10

type Runner struct {
	im   func() *Importer
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRunner() *Runner {
	return &Runner{im: Live, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Runner) Signature() string { return "vpn-panel:import-deadline" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	im := r.im()
	every := time.Duration(im.System.ConfirmTimeout()) * time.Second / checkShare
	if every < time.Second {
		every = time.Second
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		r.check(im)
		select {
		case <-r.stop:
			return nil
		case <-tick.C:
		}
	}
}

func (r *Runner) check(im *Importer) {
	if done, err := im.Expire(); err != nil {
		log.Printf("vpn-panel: откат неподтверждённого импорта не удался, повтор на следующем такте: %v", err)
	} else if done {
		log.Printf("vpn-panel: импорт настроек не подтверждён в срок и откачен")
	}
}

func (r *Runner) Shutdown() error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}
