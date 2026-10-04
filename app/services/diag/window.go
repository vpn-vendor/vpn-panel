package diag

import (
	"errors"
	"strconv"
	"time"
)

const (
	SettingWindowUntil    = "diag.window_until"
	SettingWindowFull     = "diag.window_full"
	SettingWindowMaxHours = "diag.window_max_hours"
)

const (
	WindowDefault  = 2 * time.Hour
	WindowMaxHours = 24
	WindowMinutes  = 1
	WindowMaxHrsHi = 24
)

type WindowState struct {
	Open        bool
	Until       time.Time
	FullAllowed bool
	MaxHours    int
}

func (w WindowState) Remaining(now time.Time) time.Duration {
	if !w.Open || !now.Before(w.Until) {
		return 0
	}
	return w.Until.Sub(now)
}

type WindowStore interface {
	Get(key string) string
	Set(key, value string) error
}

type Window struct {
	store WindowStore
	now   func() time.Time
}

func NewWindow(store WindowStore) *Window { return &Window{store: store, now: time.Now} }

func (w *Window) MaxHours() int {
	if v, err := strconv.Atoi(w.store.Get(SettingWindowMaxHours)); err == nil && v >= 1 && v <= WindowMaxHrsHi {
		return v
	}
	return WindowMaxHours
}

func (w *Window) State() WindowState {
	st := WindowState{MaxHours: w.MaxHours(), FullAllowed: w.store.Get(SettingWindowFull) == "1"}
	u, err := strconv.ParseInt(w.store.Get(SettingWindowUntil), 10, 64)
	if err != nil || u <= 0 {
		return st
	}
	st.Until = time.Unix(u, 0)
	st.Open = w.now().Before(st.Until)
	if !st.Open {
		st.FullAllowed = false
	}
	return st
}

var ErrWindowTooLong = errors.New("срок окна вне допустимых границ")

func (w *Window) clamp(d time.Duration) (time.Duration, error) {
	maxD := time.Duration(w.MaxHours()) * time.Hour
	if d < WindowMinutes*time.Minute || d > maxD {
		return 0, ErrWindowTooLong
	}
	return d, nil
}

func (w *Window) Open(d time.Duration, full bool) (WindowState, error) {
	d, err := w.clamp(d)
	if err != nil {
		return WindowState{}, err
	}
	until := w.now().Add(d)
	if err := w.store.Set(SettingWindowUntil, strconv.FormatInt(until.Unix(), 10)); err != nil {
		return WindowState{}, err
	}
	if err := w.store.Set(SettingWindowFull, boolValue(full)); err != nil {
		return WindowState{}, err
	}
	return w.State(), nil
}

func (w *Window) Extend(d time.Duration) (WindowState, error) {
	st := w.State()
	if !st.Open {
		return st, errors.New("окно закрыто — откройте заново")
	}
	newUntil := st.Until.Add(d)
	if _, err := w.clamp(newUntil.Sub(w.now())); err != nil {
		return st, err
	}
	if err := w.store.Set(SettingWindowUntil, strconv.FormatInt(newUntil.Unix(), 10)); err != nil {
		return st, err
	}
	return w.State(), nil
}

func (w *Window) Close() error {
	if err := w.store.Set(SettingWindowUntil, ""); err != nil {
		return err
	}
	return w.store.Set(SettingWindowFull, "0")
}

func (w *Window) FitOpenTo(h int) error {
	if st := w.State(); st.Open {
		if limit := w.now().Add(time.Duration(h) * time.Hour); st.Until.After(limit) {
			return w.store.Set(SettingWindowUntil, strconv.FormatInt(limit.Unix(), 10))
		}
	}
	return nil
}

type dbWindowStore struct{ s *Service }

func (d dbWindowStore) Get(key string) string       { return d.s.setting(key, "") }
func (d dbWindowStore) Set(key, value string) error { return d.s.setSetting(key, value) }

func (s *Service) Window() *Window { return NewWindow(dbWindowStore{s: s}) }
