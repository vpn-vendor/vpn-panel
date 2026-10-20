package listen

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/bindset"
	"github.com/vpn-vendor/vpn-panel-core/internal/multilisten"
)

type logRecorder struct{ lines []string }

func (r *logRecorder) logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *logRecorder) count(prefix string) int {
	n := 0
	for _, l := range r.lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

const (
	pendingLine = "listener: bind pending"
	clearedLine = "listener: all addresses bound again"
)

func TestNoteBindLogsOnlyChanges(t *testing.T) {
	loBusy := errors.New("127.0.0.1:80: listen tcp4 127.0.0.1:80: bind: address already in use")
	lanBusy := errors.New("192.168.11.1:80: listen tcp4 192.168.11.1:80: bind: address already in use")
	loGone := errors.New("127.0.0.1:80: listen tcp4 127.0.0.1:80: bind: cannot assign requested address")
	both := errors.Join(loBusy, lanBusy)

	cases := []struct {
		name    string
		ticks   []error
		pending int
		cleared int
	}{
		{"одна и та же неудача на каждом такте", []error{loBusy, loBusy, loBusy, loBusy}, 1, 0},
		{"неудачи кончились", []error{loBusy, loBusy, nil, nil}, 1, 1},
		{"сменился набор адресов", []error{loBusy, both, both, loBusy}, 3, 0},
		{"сменился текст ошибки", []error{loBusy, loGone, loGone}, 2, 0},
		{"без неудач журнал молчит", []error{nil, nil, nil}, 0, 0},
		{"неудача вернулась", []error{loBusy, nil, loBusy, loBusy}, 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &logRecorder{}
			m := &Manager{logf: rec.logf}
			l := multilisten.New(80, nil)
			for _, err := range tc.ticks {
				m.noteBind(l, err, bindset.ModeRoles)
			}
			if got := rec.count(pendingLine); got != tc.pending {
				t.Errorf("строк «bind pending» = %d, ждали %d: %q", got, tc.pending, rec.lines)
			}
			if got := rec.count(clearedLine); got != tc.cleared {
				t.Errorf("строк о конце неудач = %d, ждали %d: %q", got, tc.cleared, rec.lines)
			}
		})
	}
}

func TestNoteBindPerListener(t *testing.T) {
	rec := &logRecorder{}
	m := &Manager{logf: rec.logf}
	https, redirect := multilisten.New(443, nil), multilisten.New(80, nil)
	busy := errors.New("127.0.0.1:80: listen tcp4 127.0.0.1:80: bind: address already in use")
	for range 3 {
		m.noteBind(https, busy, bindset.ModeRoles)
		m.noteBind(redirect, busy, bindset.ModeRoles)
	}
	if got := rec.count(pendingLine); got != 2 {
		t.Fatalf("строк «bind pending» = %d, ждали 2: %q", got, rec.lines)
	}
	m.noteBind(redirect, nil, bindset.ModeRoles)
	if got := rec.count(clearedLine); got != 1 || !strings.HasSuffix(rec.lines[len(rec.lines)-1], "(port 80)") {
		t.Fatalf("конец неудач редиректа: %q", rec.lines)
	}
}

func TestRefreshLogsOnceAndSnapshotsInUse(t *testing.T) {
	occupant, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupant.Close() }()
	busyPort := occupant.Addr().(*net.TCPAddr).Port

	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	rec := &logRecorder{}
	https, redirect := multilisten.New(freePort, nil), multilisten.New(busyPort, nil)
	defer func() { _ = https.Close(); _ = redirect.Close() }()
	m := &Manager{
		https:    https,
		redirect: redirect,

		applied: func() []string { return []string{"127.0.0.1/8"} },
		logf:    rec.logf,
	}

	for range 4 {
		m.Refresh()
	}
	if got := rec.count(pendingLine); got != 1 {
		t.Fatalf("строк «bind pending» за 4 такта = %d: %q", got, rec.lines)
	}
	v := m.Snapshot()
	if !reflect.DeepEqual(v.Bound, []string{"127.0.0.1"}) || len(v.InUse) != 0 {
		t.Fatalf("HTTPS: Bound = %v, InUse = %v", v.Bound, v.InUse)
	}
	if _, ok := v.RedirectInUse["127.0.0.1"]; !ok || len(v.RedirectBound) != 0 {
		t.Fatalf("редирект: RedirectBound = %v, RedirectInUse = %v", v.RedirectBound, v.RedirectInUse)
	}

	if err := occupant.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		m.Refresh()
	}
	if got := rec.count(pendingLine); got != 1 {
		t.Fatalf("лишняя строка «bind pending»: %q", rec.lines)
	}
	if got := rec.count(clearedLine); got != 1 {
		t.Fatalf("строк о конце неудач = %d: %q", got, rec.lines)
	}
	v = m.Snapshot()
	if !reflect.DeepEqual(v.RedirectBound, []string{"127.0.0.1"}) || len(v.RedirectInUse) != 0 {
		t.Fatalf("редирект после ухода чужого: RedirectBound = %v, RedirectInUse = %v", v.RedirectBound, v.RedirectInUse)
	}
}
