package pathmon

import (
	"sync"
	"time"
)

type Runner struct {
	s    *Service
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRunner(s *Service) *Runner {
	return &Runner{s: s, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Runner) Signature() string { return "vpn-panel:pathmon" }
func (r *Runner) ShouldRun() bool   { return true }

func (r *Runner) Run() error {
	defer close(r.done)
	tick := time.NewTicker(ResolveEvery)
	defer tick.Stop()
	r.s.Resolve()
	for {
		select {
		case <-r.stop:
			r.s.rebuild(Roles{}, "")
			return nil
		case <-tick.C:
			r.s.Resolve()
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
