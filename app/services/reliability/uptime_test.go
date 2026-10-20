package reliability

import (
	"testing"
	"time"
)

var u0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func uat(h float64) time.Time { return u0.Add(time.Duration(h * float64(time.Hour))) }

func input(events []Event, lives []Life, cells int) UptimeInput {
	return UptimeInput{Up: "up", Down: "down", NoAnswer: "na", Events: events, Lives: lives,
		From: uat(0), Now: uat(24), Cells: cells}
}

func TestUptimeSeparatesProviderFromPowerLoss(t *testing.T) {
	lives := []Life{
		{Booted: uat(-1), Started: uat(-1), Seen: uat(12)},
		{Booted: uat(15), Started: uat(15), Seen: uat(24)},
	}
	events := []Event{
		{Code: "up", At: uat(-0.5)},
		{Code: "down", At: uat(5)},
		{Code: "up", At: uat(6)},
		{Code: "up", At: uat(15.5)},
	}
	u := ComputeUptime(input(events, lives, 24))
	if u.Down != time.Hour || u.Outages != 1 {
		t.Fatalf("простой %v, обрывов %d", u.Down, u.Outages)
	}
	if u.Off != 3*time.Hour || u.Offs != 1 {
		t.Fatalf("выключен %v, раз %d", u.Off, u.Offs)
	}

	if u.Up != 19*time.Hour+30*time.Minute {
		t.Fatalf("работал %v", u.Up)
	}
	if p, ok := u.Percent(); !ok || p < 95.1 || p > 95.2 {
		t.Fatalf("доля %v %v", p, ok)
	}
	want := map[int]Span{0: SpanUp, 5: SpanDown, 12: SpanOff, 14: SpanOff, 15: SpanUp, 23: SpanUp}
	for i, s := range want {
		if u.Cells[i] != s {
			t.Errorf("ячейка %d: %v, ждали %v", i, u.Cells[i], s)
		}
	}
}

func TestUptimeShortOutageMarksCell(t *testing.T) {
	events := []Event{{Code: "up", At: uat(-1)}, {Code: "down", At: uat(3.1)}, {Code: "up", At: uat(3.15)}}
	u := ComputeUptime(input(events, nil, 6))
	if u.Cells[0] != SpanDown || u.Cells[1] != SpanUp {
		t.Fatalf("ячейки %v", u.Cells)
	}
}

func TestUptimeUnobservedIsNotPerfect(t *testing.T) {
	u := ComputeUptime(input(nil, []Life{{Booted: uat(-1), Started: uat(-1), Seen: uat(24)}}, 4))
	if _, ok := u.Percent(); ok {
		t.Fatalf("без наблюдения есть доля: %+v", u)
	}
	for _, c := range u.Cells {
		if c != SpanUnknown {
			t.Fatalf("ячейки %v", u.Cells)
		}
	}

	events := []Event{{Code: "up", At: uat(1)}, {Code: "na", At: uat(2)}}
	u = ComputeUptime(UptimeInput{Up: "up", Down: "down", NoAnswer: "na", Events: events,
		Breaks: []time.Time{uat(10)}, From: uat(0), Now: uat(24)})
	if u.Up != time.Hour || u.Down != 0 {
		t.Fatalf("работал %v простой %v", u.Up, u.Down)
	}
}

func TestUptimeOutageBeforeWindow(t *testing.T) {
	events := []Event{{Code: "down", At: uat(-2)}, {Code: "up", At: uat(1)}}
	u := ComputeUptime(input(events, nil, 0))
	if u.Down != time.Hour || u.Outages != 1 || u.Up != 23*time.Hour {
		t.Fatalf("%+v", u)
	}
}
