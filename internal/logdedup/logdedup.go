package logdedup

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	Window  = 5 * time.Second
	Burst   = 10
	MaxKeys = 512
)

type Writer struct {
	out     io.Writer
	window  time.Duration
	burst   int
	maxKeys int
	now     func() time.Time

	mu        sync.Mutex
	keys      map[string]*state
	lastSweep time.Time
}

type state struct {
	start      time.Time
	seen       int
	suppressed int
}

func New(out io.Writer) *Writer {
	return newWriter(out, Window, Burst, MaxKeys, time.Now)
}

func newWriter(out io.Writer, window time.Duration, burst, maxKeys int, now func() time.Time) *Writer {
	return &Writer{out: out, window: window, burst: burst, maxKeys: maxKeys, now: now, keys: map[string]*state{}}
}

func (w *Writer) Write(p []byte) (int, error) {
	line := string(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if now.Sub(w.lastSweep) >= w.window {
		w.sweep(now)
	}

	st, ok := w.keys[line]
	if ok && now.Sub(st.start) >= w.window {
		w.summary(line, st)
		delete(w.keys, line)
		ok = false
	}
	if !ok {
		if len(w.keys) >= w.maxKeys {
			w.sweep(now)
		}
		if len(w.keys) >= w.maxKeys {

			_, err := w.out.Write(p)
			return len(p), err
		}
		st = &state{start: now}
		w.keys[line] = st
	}
	st.seen++
	if st.seen > w.burst {
		st.suppressed++
		return len(p), nil
	}
	_, err := w.out.Write(p)
	return len(p), err
}

func (w *Writer) sweep(now time.Time) {
	w.lastSweep = now
	for line, st := range w.keys {
		if now.Sub(st.start) >= w.window {
			w.summary(line, st)
			delete(w.keys, line)
		}
	}
}

func (w *Writer) summary(line string, st *state) {
	if st.suppressed == 0 {
		return
	}
	_, _ = fmt.Fprintf(w.out, "повторено ещё %d раз за %s: %s\n", st.suppressed, w.window, strings.TrimRight(line, "\n"))
}

func (w *Writer) Keys() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.keys)
}
