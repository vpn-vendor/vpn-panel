package network

import (
	"log"
	"sync"
	"time"
)

const reconcileShare = 10

type Runner struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRunner() *Runner { return &Runner{stop: make(chan struct{}), done: make(chan struct{})} }

func (r *Runner) Signature() string { return "vpn-panel:network-settle" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	s := New()
	every := time.Duration(s.ConfirmTimeout()) * time.Second / reconcileShare
	if every < time.Second {
		every = time.Second
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if reverted, err := s.Reconcile(); err != nil {
			log.Printf("vpn-panel: настройки сети не приведены к действующим, повтор на следующем такте: %v", err)
		} else if reverted {
			log.Printf("vpn-panel: изменение сети не подтверждено — настройки возвращены к действующим")
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
