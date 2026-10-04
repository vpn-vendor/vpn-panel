package diag

import (
	"errors"
	"strconv"
	"time"
)

const (
	SettingFullCheckUntil = "diag.fullcheck_until"

	FullCheckMinutes = 1
)

type FullCheckState struct {
	Active bool
	Until  time.Time
}

func (f FullCheckState) Remaining(now time.Time) time.Duration {
	if !f.Active || !now.Before(f.Until) {
		return 0
	}
	return f.Until.Sub(now)
}

type FullCheck struct {
	store WindowStore
	now   func() time.Time
	audit func(event, ip, details string)
	max   func() int
}

func (s *Service) FullCheck() *FullCheck {
	w := s.Window()
	return &FullCheck{store: dbWindowStore{s: s}, now: time.Now, audit: s.Audit, max: w.MaxHours}
}

func (f *FullCheck) State() FullCheckState {
	u, err := strconv.ParseInt(f.store.Get(SettingFullCheckUntil), 10, 64)
	if err != nil || u <= 0 {
		return FullCheckState{}
	}
	until := time.Unix(u, 0)
	if f.now().Before(until) {
		return FullCheckState{Active: true, Until: until}
	}
	_ = f.store.Set(SettingFullCheckUntil, "")
	if f.audit != nil {
		f.audit("lan_fullcheck_ended", "", "срок вышел, пределы возвращены автоматически")
	}
	return FullCheckState{}
}

func (f *FullCheck) Start(d time.Duration, consent bool, ip string) (FullCheckState, error) {
	if !consent {
		return FullCheckState{}, errors.New("нужно явно подтвердить, что пределы будут сняты")
	}
	maxD := time.Duration(f.max()) * time.Hour
	if d < FullCheckMinutes*time.Minute || d > maxD {
		return FullCheckState{}, ErrWindowTooLong
	}
	until := f.now().Add(d)
	if err := f.store.Set(SettingFullCheckUntil, strconv.FormatInt(until.Unix(), 10)); err != nil {
		return FullCheckState{}, err
	}
	if f.audit != nil {
		f.audit("lan_fullcheck_started", ip, "до "+until.Local().Format("02.01.2006 15:04:05")+": сняты все пределы проверки скорости, качество звонков не гарантируется")
	}
	return FullCheckState{Active: true, Until: until}, nil
}

func (f *FullCheck) Stop(ip string) error {
	if err := f.store.Set(SettingFullCheckUntil, ""); err != nil {
		return err
	}
	if f.audit != nil {
		f.audit("lan_fullcheck_stopped", ip, "остановлено администратором, пределы возвращены")
	}
	return nil
}

func ExpireFullCheck() { New().FullCheck().State() }
