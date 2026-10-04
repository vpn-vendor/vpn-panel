package diag

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

func TestVisibleLabelRule(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		d    models.Device
		want string
	}{
		{"видимое поле", models.Device{PublicLabel: "ПК Ирины", Label: "служебное", Note: "на увольнение"}, "ПК Ирины"},
		{"прежняя подпись до пересмотра", models.Device{Label: "ПК", Location: "бухгалтерия", Owner: "Ирина"}, "ПК · бухгалтерия · Ирина"},
		{"пересмотрена, видимое пусто", models.Device{Label: "служебное", LabelReviewedAt: &now}, ""},
		{"пусто вовсе", models.Device{}, ""},
	}
	for _, c := range cases {
		if got := VisibleLabel(c.d); got != c.want {
			t.Errorf("%s: %q, ожидалось %q", c.name, got, c.want)
		}
	}
	if MaxPublicLabel != 120 {
		t.Fatal("предел видимой подписи изменён")
	}
}
