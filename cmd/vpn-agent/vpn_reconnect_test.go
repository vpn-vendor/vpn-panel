package main

import (
	"testing"
	"time"
)

func TestManualWait(t *testing.T) {
	at := bootInstant(10 * time.Minute)
	if w := manualWait(0, at); w != 0 {
		t.Fatalf("без нажатий: %v", w)
	}
	if w := manualWait(at, at.Add(20*time.Second)); w != 40*time.Second {
		t.Fatalf("через 20 с: %v", w)
	}
	if w := manualWait(at, at.Add(manualRetryGap)); w != 0 {
		t.Fatalf("через минуту: %v", w)
	}
}

func TestReconnectRefusal(t *testing.T) {
	if e := reconnectRefusal(modeWhite, "fra", 0); e == nil || e.Code != codeVPNParams {
		t.Fatalf("прямой режим: %+v", e)
	}
	if e := reconnectRefusal(modeBlack, "", 0); e == nil {
		t.Fatal("без подключения переподключение принято")
	}
	e := reconnectRefusal(modeBlack, "fra", 1500*time.Millisecond)
	if e == nil || e.Code != codeVPNBusy || e.Data["retry_in_sec"] != int64(2) {
		t.Fatalf("слишком часто: %+v", e)
	}
	if e := reconnectRefusal(modeBlack, "fra", 0); e != nil {
		t.Fatalf("можно, а отказано: %+v", e)
	}
}
