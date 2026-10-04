package agentrpc

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBusyRetryAfterSurvivesTheWire(t *testing.T) {
	raw, err := json.Marshal(Busy(1001, "подождите", 1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorObject
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wait, ok := got.RetryAfter()
	if !ok || wait != 2*time.Second || !got.Recoverable() {
		t.Fatalf("после сокета: срок %v (есть: %v), повторимо: %v", wait, ok, got.Recoverable())
	}
	if w, ok := Busy(1001, "подождите", 0).RetryAfter(); !ok || w != time.Second {
		t.Fatalf("нулевой срок обязан стать секундой, а не пропасть: %v %v", w, ok)
	}
	plain := &ErrorObject{Code: 1002, Message: "план", Data: map[string]any{"recoverable": false}}
	if _, ok := plain.RetryAfter(); ok || plain.Recoverable() {
		t.Fatal("обычный отказ срока не называет")
	}
}
