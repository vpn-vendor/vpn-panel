package restore

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

type scriptedAgent struct {
	answers []error
	calls   int
}

func (a *scriptedAgent) Call(string, any, any) error {
	err := a.answers[a.calls]
	a.calls++
	return err
}

func TestPatientAgentWaitsNamedPauseOnce(t *testing.T) {
	busy := agentrpc.Busy(2104, "слишком часто", 7*time.Second)
	inner := &scriptedAgent{answers: []error{busy, nil}}
	var slept, told time.Duration
	p := patientAgent{inner: inner, sleep: func(d time.Duration) { slept = d }, tell: func(d time.Duration) { told = d }}
	if err := p.Call("backup.export", nil, nil); err != nil {
		t.Fatalf("после паузы вызов обязан пройти: %v", err)
	}
	if slept != 7*time.Second || told != slept || inner.calls != 2 {
		t.Fatalf("пауза %v, сказано %v, вызовов %d", slept, told, inner.calls)
	}

	inner = &scriptedAgent{answers: []error{busy, busy}}
	p = patientAgent{inner: inner, sleep: func(time.Duration) {}}
	if err := p.Call("backup.export", nil, nil); err == nil || inner.calls != 2 {
		t.Fatalf("второй отказ возвращается человеку, вызовов %d, ошибка %v", inner.calls, err)
	}

	plain := &agentrpc.ErrorObject{Code: 2105, Message: "пароль не подошёл", Data: map[string]any{"recoverable": true}}
	inner = &scriptedAgent{answers: []error{plain}}
	p = patientAgent{inner: inner, sleep: func(time.Duration) { t.Fatal("отказ без срока не пережидается") }}
	if err := p.Call("backup.open", nil, nil); err == nil || inner.calls != 1 {
		t.Fatalf("отказ без срока: вызовов %d", inner.calls)
	}
}
