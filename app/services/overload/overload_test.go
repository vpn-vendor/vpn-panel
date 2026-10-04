package overload

import "testing"

func TestThresholdsFrozen(t *testing.T) {
	if PressureHot != 50.0 || ThrottleHotShare != 0.5 {
		t.Fatalf("пороги изменены: давление %v, торможение %v", PressureHot, ThrottleHotShare)
	}
	if len(Signals()) != 2 {
		t.Fatalf("сигналов %d, ожидалось два: давление и торможение", len(Signals()))
	}
}
