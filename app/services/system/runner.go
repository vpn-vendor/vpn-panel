package system

import (
	"log"
	"sync"
	"time"
)

const ReconcileEvery = time.Minute

type Runner struct {
	r    *Reconciler
	sync *SurroundSync
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRunner(r *Reconciler, sync *SurroundSync) *Runner {
	return &Runner{r: r, sync: sync, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Runner) Signature() string { return "vpn-panel:host-reconcile" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	tick := time.NewTicker(ReconcileEvery)
	defer tick.Stop()
	for {
		if redone, err := r.r.Step(); err != nil {
			log.Printf("vpn-panel: сверка с паспортом системы не прошла, повтор на следующем шаге: %v", err)
		} else if len(redone) > 0 {
			log.Printf("vpn-panel: перерисованы под систему: %v", redone)
		}
		if r.sync != nil {
			if err := r.sync.Step(); err != nil {
				log.Printf("vpn-panel: обстановка шлюза не прочитана, повтор на следующем шаге: %v", err)
			}
		}
		select {
		case <-r.stop:
			return nil
		case <-tick.C:
		}
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
