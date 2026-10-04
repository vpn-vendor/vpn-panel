package auth

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

func TestDiedAt(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	sliding := 72 * time.Hour
	ago := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	later := now.Add(10 * 24 * time.Hour)
	revoked := ago(5)
	cases := []struct {
		name string
		d    models.TrustedDevice
		want time.Time
	}{
		{"живое", models.TrustedDevice{LastUsedAt: ago(1), AbsoluteExpiresAt: later}, time.Time{}},
		{"простой дольше срока", models.TrustedDevice{LastUsedAt: ago(100), AbsoluteExpiresAt: later}, ago(100).Add(sliding)},
		{"абсолютный потолок", models.TrustedDevice{LastUsedAt: ago(1), AbsoluteExpiresAt: ago(2)}, ago(2)},
		{"отозвано", models.TrustedDevice{LastUsedAt: ago(1), AbsoluteExpiresAt: later, RevokedAt: &revoked}, revoked},
		{"раньше всех — потолок", models.TrustedDevice{LastUsedAt: ago(200), AbsoluteExpiresAt: ago(190), RevokedAt: &revoked}, ago(190)},
	}
	for _, c := range cases {
		got := DiedAt(c.d, now, sliding)
		if !got.Equal(c.want) {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
		if Alive(c.d, now, sliding) != c.want.IsZero() {
			t.Errorf("%s: Alive расходится с DiedAt", c.name)
		}
	}
}
