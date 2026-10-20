package nftgen

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

func TestProbePlanCoversGenerator(t *testing.T) {
	p := ProbePlan()
	if zero := hostcaps.ZeroFields(p); len(zero) > 0 {
		t.Fatalf("пробный план не задействует поля %v", zero)
	}
	if err := p.Validate(nil); err != nil {
		t.Fatalf("пробный план не проходит проверку: %v", err)
	}
	if !p.Black() {
		t.Fatal("пробный план обязан включать защищённый режим")
	}
	if len(p.Generate(Caps{})) == 0 {
		t.Fatal("пустой набор правил")
	}
}
