package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftwatch"
)

type guardKernel struct {
	table   tableShape
	fwd     bool
	fwdLog  []bool
	loaded  []string
	fail    map[string]bool
	shapes  map[string]tableShape
	now     time.Time
	unknown bool
}

func (k *guardKernel) sys() guardSys {
	return guardSys{
		now:   func() time.Time { return k.now },
		shape: func() (tableShape, bool) { return k.table, !k.unknown },
		load: func(r []byte) error {
			k.loaded = append(k.loaded, string(r))
			if k.fail[string(r)] {
				return errors.New("не принят")
			}
			k.table = k.shapes[string(r)]
			return nil
		},
		setForward: func(on bool) bool { k.fwd = on; k.fwdLog = append(k.fwdLog, on); return true },
		forward:    func() (bool, bool) { return k.fwd, true },
		emergency:  func() []byte { return []byte("аварийный") },
	}
}

var (
	workingShape   = tableShape{present: true, body: "chain forward\nrules forward 9"}
	emergencyShape = tableShape{present: true, body: "chain forward\nrules forward 2"}
)

func guardFixture() (*firewallApplier, *guardKernel) {
	k := &guardKernel{table: workingShape, fwd: true, now: time.Unix(1_800_000_000, 0),
		shapes: map[string]tableShape{"рабочий": workingShape, "аварийный": emergencyShape}, fail: map[string]bool{}}
	f := &firewallApplier{}
	f.guard.sys = k.sys()
	f.held = heldState{ruleset: []byte("рабочий"), working: true, forward: true}
	f.guard.shape = workingShape
	return f, k
}

var eraser = writer{pid: 4242, comm: "nft", unit: "nftables.service"}

func TestGuardLeavesIntactTable(t *testing.T) {
	f, k := guardFixture()
	_, changed := f.guardCheck(eraser)
	if changed || len(k.loaded) != 0 || len(k.fwdLog) != 0 {
		t.Fatalf("целая таблица тронута: changed=%v loaded=%v fwd=%v", changed, k.loaded, k.fwdLog)
	}
}

func TestGuardReturnsErasedTable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table tableShape
	}{
		{"таблицу стёрли", tableShape{}},

		{"таблицу искалечили", tableShape{present: true, body: "chain forward"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, k := guardFixture()
			k.table = tc.table
			_, changed := f.guardCheck(eraser)
			if !changed {
				t.Fatal("сторож не заметил пропажу")
			}
			if strings.Join(k.loaded, ",") != "рабочий" {
				t.Fatalf("загружено %v, ждали рабочий набор", k.loaded)
			}

			if len(k.fwdLog) != 2 || k.fwdLog[0] || !k.fwdLog[1] {
				t.Fatalf("пересылка %v, ждали [false true]", k.fwdLog)
			}
			g := f.guard
			if g.emergency || g.returns != 1 || g.erasures != 1 || g.eraser != eraser || g.pause != guardPauseFirst {
				t.Fatalf("состояние сторожа %+v", g)
			}
		})
	}
}

func TestGuardTugOfWarClosesOffice(t *testing.T) {
	f, k := guardFixture()
	k.table = tableShape{}
	f.guardCheck(eraser)

	k.now = k.now.Add(guardPauseFirst / 2)
	k.table = tableShape{}
	wait, _ := f.guardCheck(eraser)
	if !f.guard.emergency || k.fwd || k.loaded[len(k.loaded)-1] != "аварийный" {
		t.Fatalf("ждали аварийный набор: emergency=%v fwd=%v loaded=%v", f.guard.emergency, k.fwd, k.loaded)
	}
	if wait > guardPauseFirst/2 {
		t.Fatalf("сторож проснётся через %v, пауза кончится через %v", wait, guardPauseFirst/2)
	}

	k.now = k.now.Add(guardPauseFirst / 4)
	f.guardCheck(writer{})
	if k.loaded[len(k.loaded)-1] != "аварийный" || !f.guard.emergency {
		t.Fatalf("рабочий набор вернулся раньше паузы: %v", k.loaded)
	}

	k.now = k.now.Add(guardPauseFirst)
	f.guardCheck(writer{})
	if f.guard.emergency || k.loaded[len(k.loaded)-1] != "рабочий" || !k.fwd {
		t.Fatalf("рабочий набор не вернулся: %v fwd=%v", k.loaded, k.fwd)
	}
	if f.guard.pause != 2*guardPauseFirst {
		t.Fatalf("пауза %v, ждали %v", f.guard.pause, 2*guardPauseFirst)
	}
}

func TestGuardRejectedWorkingSetStaysClosed(t *testing.T) {
	f, k := guardFixture()
	k.table = tableShape{}
	k.fail["рабочий"] = true
	f.guardCheck(eraser)
	if !f.guard.failed || !f.guard.emergency || k.fwd {
		t.Fatalf("ждали аварийный набор и выключенную пересылку: %+v fwd=%v", f.guard, k.fwd)
	}
}

func TestGuardForwardOnlyIfWeEnabledIt(t *testing.T) {
	f, k := guardFixture()

	f.held.forward = false
	k.fwd = false
	k.table = tableShape{}
	f.guardCheck(eraser)
	if k.fwd {
		t.Fatal("сторож включил пересылку, которую мы не включали")
	}
	f.guardCheck(writer{})
	if k.fwd {
		t.Fatal("сторож включил пересылку при целой таблице")
	}
}

func TestGuardReturnsForwarding(t *testing.T) {
	f, k := guardFixture()
	k.fwd = false
	_, changed := f.guardCheck(writer{})
	if !changed || !k.fwd || f.guard.fwdReturns != 1 {
		t.Fatalf("пересылка не вернулась: fwd=%v %+v", k.fwd, f.guard)
	}

	k.now = k.now.Add(guardPauseFirst / 2)
	k.fwd = false
	f.guardCheck(writer{})
	if k.fwd || !f.guard.fwdOffNow {
		t.Fatalf("пересылка включена раньше паузы или не замечена: fwd=%v %+v", k.fwd, f.guard)
	}

	f2, k2 := guardFixture()
	f2.held.working = false
	k2.fwd = false
	f2.guardCheck(writer{})
	if k2.fwd {
		t.Fatal("пересылка включена при аварийном наборе")
	}
}

func TestGuardForgetsAfterCalm(t *testing.T) {
	f, k := guardFixture()
	k.table = tableShape{}
	f.guardCheck(eraser)
	k.now = k.now.Add(guardCalm)
	_, changed := f.guardCheck(writer{})
	if !changed || !f.guard.erasedAt.IsZero() || f.guard.pause != 0 {
		t.Fatalf("прошлое не забыто: %+v", f.guard)
	}
}

func TestGuardIdleWithoutOwnRules(t *testing.T) {
	f, k := guardFixture()
	f.held = heldState{}
	k.table = tableShape{}
	k.fwd = false
	f.guardCheck(eraser)
	if len(k.loaded) != 0 || len(k.fwdLog) != 0 {
		t.Fatalf("сторож тронул систему без своих правил: %v %v", k.loaded, k.fwdLog)
	}

	f2, k2 := guardFixture()
	k2.unknown = true
	k2.table = tableShape{}
	f2.guardCheck(eraser)
	if len(k2.loaded) != 0 {
		t.Fatal("сторож действовал без ответа nft")
	}
}

func TestParseShapeIgnoresCounters(t *testing.T) {
	base := `{"nftables":[{"metainfo":{"version":"1.0.2"}},{"table":{"family":"inet","name":"vpn_panel","handle":7}},` +
		`{"chain":{"family":"inet","table":"vpn_panel","name":"forward","handle":1,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},` +
		`{"counter":{"family":"inet","name":"seen_early","table":"vpn_panel","handle":2,"packets":%d,"bytes":0}},` +
		`{"rule":{"family":"inet","table":"vpn_panel","chain":"forward","handle":3,"expr":[{"accept":null}]}}%s]}`
	a := parseShape([]byte(strings.Replace(strings.Replace(base, "%d", "1", 1), "%s", "", 1)))
	b := parseShape([]byte(strings.Replace(strings.Replace(base, "%d", "999", 1), "%s", "", 1)))
	if !a.same(b) || a.handle != 7 {
		t.Fatalf("счётчик поменял структуру: %q против %q", a.body, b.body)
	}

	extra := `,{"rule":{"family":"inet","table":"vpn_panel","chain":"forward","handle":4,"expr":[{"drop":null}]}}`
	c := parseShape([]byte(strings.Replace(strings.Replace(base, "%d", "1", 1), "%s", extra, 1)))
	if a.same(c) {
		t.Fatal("лишнее правило не замечено")
	}
	if a.same(tableShape{}) {
		t.Fatal("целая таблица равна пропавшей")
	}
}

func TestHasTable(t *testing.T) {
	list := []byte(`{"nftables":[{"metainfo":{}},{"table":{"family":"ip","name":"filter","handle":1}},{"table":{"family":"inet","name":"vpn_panel","handle":9}}]}`)
	if !hasTable(list, "inet", "vpn_panel") || hasTable(list, "inet", "vpn_panel_dhcp") || hasTable(list, "ip", "vpn_panel") {
		t.Fatal("hasTable ошибся")
	}
}

func TestOwnChildren(t *testing.T) {
	noteChild(31337)
	if !isOwnChild(31337) || isOwnChild(31338) {
		t.Fatal("кольцо своих процессов ошиблось")
	}
	if _, foreign := eventWriterFor(31337); foreign {
		t.Fatal("свой процесс принят за чужой")
	}
}

func eventWriterFor(pid int) (writer, bool) {
	return eventWriter(nftwatch.Event{PID: pid, Comm: "nft"}, "")
}

func TestOwnLoadAfterEmergencyReturnsForwarding(t *testing.T) {
	working := "table inet vpn_panel {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"wan0\" masquerade\n\t}\n}\n"
	f, k := guardFixture()
	k.shapes[working] = workingShape
	k.table = tableShape{}
	f.guardCheck(eraser)
	k.now = k.now.Add(guardPauseFirst / 2)
	k.table = tableShape{}
	f.guardCheck(eraser)
	if !f.guard.emergency || k.fwd {
		t.Fatalf("ждали аварийный набор: %+v fwd=%v", f.guard, k.fwd)
	}
	k.table = workingShape
	f.noteLoad([]byte(working))
	if !k.fwd || f.guard.emergency {
		t.Fatalf("пересылка не вернулась после своей загрузки: fwd=%v %+v", k.fwd, f.guard)
	}
	f.guardCheck(writer{})
	if f.guard.fwdReturns != 0 || !f.guard.fwdOffAt.IsZero() {
		t.Fatalf("свою пересылку записали на чужую программу: %+v", f.guard)
	}

	f2, k2 := guardFixture()
	f2.guard.emergency = true
	k2.fwd = false
	f2.noteLoad([]byte("table inet vpn_panel {\n}\n"))
	if k2.fwd {
		t.Fatal("пересылка включена под аварийным набором")
	}
}

func TestGuardHoldsTunnelWatchdog(t *testing.T) {
	f, k := guardFixture()
	stale := 3 * time.Minute
	if f.guardHolds(stale) {
		t.Fatal("целая таблица держит сторожа канала")
	}
	k.table = tableShape{}
	f.guardCheck(eraser)
	k.now = k.now.Add(guardPauseFirst / 2)
	k.table = tableShape{}
	f.guardCheck(eraser)
	if !f.guardHolds(stale) {
		t.Fatal("аварийный набор не держит сторожа канала")
	}
	k.now = k.now.Add(guardPauseFirst)
	f.guardCheck(writer{})
	if f.guard.emergency || !f.guardHolds(stale) {
		t.Fatalf("сразу после возврата канал ещё не успел: %+v", f.guard)
	}
	k.now = k.now.Add(stale)
	if f.guardHolds(stale) {
		t.Fatal("сторож канала держится дольше порога молчания")
	}
}
