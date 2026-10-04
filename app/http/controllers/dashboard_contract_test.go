package controllers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
)

func TestDashboardScriptAgreesWithServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "public", "js", "dashboard.js"))
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	for _, mode := range []metrics.Mode{metrics.Paused, metrics.Off} {
		if !strings.Contains(js, `"`+mode.String()+`"`) {
			t.Errorf("сценарий дашборда не знает состояния рубильника %q", mode.String())
		}
	}
	for _, chip := range (ui.WindowChips{}).Chips() {
		if !strings.Contains(js, `"`+chip.Key+`":`) {
			t.Errorf("сценарий дашборда не знает окна %q", chip.Key)
		}
	}
	for _, unit := range []string{"bits", "ms", "percent", "rate"} {
		if (ui.ChartCard{Unit: unit}).UnitName() != unit {
			t.Errorf("атом карточки не знает единицы %q", unit)
		}
		if !strings.Contains(js, `"`+unit+`"`) {
			t.Errorf("сценарий дашборда не знает единицы %q", unit)
		}
	}
	if !strings.Contains(js, `"/metrics/series?rows="`) {
		t.Error("сценарий дашборда обязан ходить в существующую конечную точку истории")
	}
}
