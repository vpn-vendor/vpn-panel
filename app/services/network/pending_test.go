package network

import "testing"

func TestReconcileStandsAsideDuringChange(t *testing.T) {
	changeMu.Lock()
	reverted, err := New().Reconcile()
	changeMu.Unlock()
	if reverted || err != nil {
		t.Fatalf("исполнитель вмешался в идущее изменение: reverted=%v err=%v", reverted, err)
	}
}
