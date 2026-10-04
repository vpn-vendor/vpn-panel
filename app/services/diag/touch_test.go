package diag

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagnose"
)

func TestNeedsWrite(t *testing.T) {
	now := time.Unix(10_000, 0)
	row := models.Device{MAC: "aa:bb:cc:dd:ee:ff", LastIP: "192.0.2.10", Hostname: "buh-1"}
	same := diagnose.Device{MAC: row.MAC, IP: row.LastIP, Hostname: row.Hostname, Online: true}
	fresh := seenMark{wrote: now.Add(-10 * time.Second)}

	cases := []struct {
		name  string
		mark  seenMark
		known bool
		d     diagnose.Device
		want  bool
	}{
		{"первый показ после старта панели", seenMark{}, false, same, true},
		{"повторный показ через 10 с", fresh, true, same, false},
		{"показ через минуту", seenMark{wrote: now.Add(-time.Minute)}, true, same, true},
		{"сменился адрес", fresh, true, diagnose.Device{MAC: row.MAC, IP: "192.0.2.11", Hostname: row.Hostname}, true},
		{"сменилось имя", fresh, true, diagnose.Device{MAC: row.MAC, IP: row.LastIP, Hostname: "buh-2"}, true},
		{"имя неизвестно в этом показе", fresh, true, diagnose.Device{MAC: row.MAC, IP: row.LastIP}, false},
	}
	for _, c := range cases {
		if got := needsWrite(c.mark, c.known, row, c.d, now); got != c.want {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

func TestRememberCeiling(t *testing.T) {
	seenMu.Lock()
	seen = map[string]seenMark{}
	seenMu.Unlock()
	now := time.Unix(10_000, 0)
	for i := 0; i < seenMaxKeys*3; i++ {
		remember(diagnose.Device{MAC: string(rune(0x1000 + i))}, now)
	}
	seenMu.Lock()
	n := len(seen)
	seenMu.Unlock()
	if n > seenMaxKeys {
		t.Fatalf("учёт вырос до %d при потолке %d", n, seenMaxKeys)
	}
}
