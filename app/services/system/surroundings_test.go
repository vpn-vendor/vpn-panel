package system

import (
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

type fakeSync struct {
	st     hostcaps.Surroundings
	stored string
	events []string
}

func (f *fakeSync) sync() *SurroundSync {
	return &SurroundSync{
		read:   func() (hostcaps.Surroundings, error) { return f.st, nil },
		load:   func() string { return f.stored },
		save:   func(v string) error { f.stored = v; return nil },
		record: func(code, _ string) { f.events = append(f.events, code) },
		now:    func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) },
	}
}

func around(answers map[string]hostcaps.Answer) hostcaps.Surroundings {
	st := hostcaps.Surroundings{TakenAt: "2026-10-19T12:00:00Z"}
	for id, a := range answers {
		st.Facts = append(st.Facts, hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: a})
	}
	return st
}

func TestSettlingWritesNothing(t *testing.T) {
	f := &fakeSync{st: hostcaps.Surroundings{Settling: true}}
	if err := f.sync().Step(); err != nil || f.stored != "" || len(f.events) != 0 {
		t.Fatalf("пока агент снимает обстановку, сверять не с чем: %v %q %v", err, f.stored, f.events)
	}
}

func TestFoundAndClearedOnce(t *testing.T) {
	f := &fakeSync{st: around(map[string]hostcaps.Answer{"surroundings.dhcp_host": hostcaps.No})}
	y := f.sync()
	_ = y.Step()
	if len(f.events) != 0 {
		t.Fatalf("чистая первая встреча не даёт событий: %v", f.events)
	}
	f.st = around(map[string]hostcaps.Answer{"surroundings.dhcp_host": hostcaps.Yes})
	_ = y.Step()
	_ = y.Step()
	f.st = around(map[string]hostcaps.Answer{"surroundings.dhcp_host": hostcaps.Unknown})
	_ = y.Step()
	f.st = around(map[string]hostcaps.Answer{"surroundings.dhcp_host": hostcaps.No})
	_ = y.Step()
	want := []string{"foreign_dhcp_found", "foreign_dhcp_cleared"}
	if len(f.events) != 2 || f.events[0] != want[0] || f.events[1] != want[1] {
		t.Fatalf("ждали %v, получили %v", want, f.events)
	}
}

func TestRerunHasNoClearedEvent(t *testing.T) {
	f := &fakeSync{st: around(map[string]hostcaps.Answer{"legacy.rerun": hostcaps.Yes})}
	y := f.sync()
	_ = y.Step()
	f.st = around(map[string]hostcaps.Answer{"legacy.rerun": hostcaps.No})
	_ = y.Step()
	if len(f.events) != 1 || f.events[0] != "legacy_rerun" {
		t.Fatalf("повтор старого скрипта — одно событие: %v", f.events)
	}
}

func TestEventCodesAreCatalogued(t *testing.T) {
	for id, codes := range eventFamily {
		for _, c := range codes {
			if c == "" {
				continue
			}
			if !catalogued(c) {
				t.Errorf("%s: кода %s нет в каталоге журнала", id, c)
			}
		}
	}
}

func catalogued(code string) bool {
	_, ok := securitylog.Lookup(code)
	return ok
}

func fwStep(id string, a hostcaps.Answer, level string) hostcaps.Surroundings {
	return hostcaps.Surroundings{TakenAt: "2026-10-19T12:00:00Z", Facts: []hostcaps.Fact{
		{ID: id, Class: hostcaps.ClassForeign, Answer: a, Level: level}}}
}

func runSteps(steps []hostcaps.Surroundings) ([]string, map[string]SeenFact) {
	f := &fakeSync{}
	y := f.sync()
	for _, st := range steps {
		f.st = st
		_ = y.Step()
	}
	return f.events, parseSeen(f.stored)
}

func TestForwardCutEventsByLevel(t *testing.T) {
	const id = "surroundings.forward_cut"
	step := func(a hostcaps.Answer, level string) hostcaps.Surroundings { return fwStep(id, a, level) }
	resetUnknown := step(hostcaps.Unknown, "")
	resetUnknown.Facts[0].Reset, resetUnknown.Facts[0].Found = true, "Шлюз смотрит заново."
	cases := []struct {
		name  string
		steps []hostcaps.Surroundings
		want  []string
		seen  string
	}{
		{"сведение без тревоги", []hostcaps.Surroundings{step(hostcaps.No, ""), step(hostcaps.Yes, hostcaps.LevelInfo)}, nil, ""},
		{"срез стал доказан", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelInfo), step(hostcaps.Yes, hostcaps.LevelError)},
			[]string{"forward_cut_found"}, ""},
		{"срез ушёл, источник жив", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelError), step(hostcaps.Yes, hostcaps.LevelWarn)},
			[]string{"forward_cut_found", "forward_cut_cleared"}, ""},

		{"срез, затем неизвестно", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelError), step(hostcaps.Unknown, "")},
			[]string{"forward_cut_found"}, hostcaps.LevelError},
		{"срез, затем сброс", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelError), resetUnknown},
			[]string{"forward_cut_found"}, hostcaps.LevelError},
		{"неизвестно не гасит срез", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelError), step(hostcaps.Unknown, ""),
			step(hostcaps.No, "")}, []string{"forward_cut_found", "forward_cut_cleared"}, ""},
		{"неизвестно, затем срез — одно событие", []hostcaps.Surroundings{step(hostcaps.Yes, hostcaps.LevelError), step(hostcaps.Unknown, ""),
			step(hostcaps.Yes, hostcaps.LevelError)}, []string{"forward_cut_found"}, ""},
	}
	for _, c := range cases {
		events, seen := runSteps(c.steps)
		if strings.Join(events, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: события %v, ждали %v", c.name, events, c.want)
		}
		if c.seen != "" && (seen[id].Answer != "yes" || seen[id].Level != c.seen) {
			t.Errorf("%s: отметка %+v, ждали «да» %s", c.name, seen[id], c.seen)
		}
	}
}

func TestHeldFactsEventsAnyLevel(t *testing.T) {
	type obs struct {
		a     hostcaps.Answer
		level string
	}
	cases := []struct {
		name  string
		id    string
		steps []obs
		want  []string
	}{
		{"пересылку выключали и вернули", "surroundings.forward_off", []obs{{hostcaps.No, ""}, {hostcaps.Yes, hostcaps.LevelWarn}, {hostcaps.No, ""}},
			[]string{"forward_off_found", "forward_off_cleared"}},
		{"пересылка выключена, шлюз включил", "surroundings.forward_off", []obs{{hostcaps.Yes, hostcaps.LevelError}, {hostcaps.Yes, hostcaps.LevelWarn}},
			[]string{"forward_off_found"}},
		{"правила стирали по кругу, потом вернули", "surroundings.own_table", []obs{{hostcaps.Yes, hostcaps.LevelError}, {hostcaps.Yes, hostcaps.LevelWarn}, {hostcaps.No, ""}},
			[]string{"own_table_found", "own_table_cleared"}},
		{"стёрли и вернули", "surroundings.own_table", []obs{{hostcaps.No, ""}, {hostcaps.Yes, hostcaps.LevelWarn}},
			[]string{"own_table_found"}},

		{"неизвестно молчит", "surroundings.forward_off", []obs{{hostcaps.Yes, hostcaps.LevelWarn}, {hostcaps.Unknown, ""}},
			[]string{"forward_off_found"}},
	}
	for _, c := range cases {
		var steps []hostcaps.Surroundings
		for _, s := range c.steps {
			steps = append(steps, fwStep(c.id, s.a, s.level))
		}
		if events, _ := runSteps(steps); strings.Join(events, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: события %v, ждали %v", c.name, events, c.want)
		}
	}
}

func TestNewFactFamilies(t *testing.T) {
	cases := map[string][2]string{
		"surroundings.dhcp_lan":    {"lan_dhcp_found", "lan_dhcp_cleared"},
		"surroundings.forward_off": {"forward_off_found", "forward_off_cleared"},
		"surroundings.own_table":   {"own_table_found", "own_table_cleared"},
	}
	for id, want := range cases {
		f := &fakeSync{st: around(map[string]hostcaps.Answer{id: hostcaps.Yes})}
		y := f.sync()
		_ = y.Step()
		f.st = around(map[string]hostcaps.Answer{id: hostcaps.No})
		_ = y.Step()
		if len(f.events) != 2 || f.events[0] != want[0] || f.events[1] != want[1] {
			t.Errorf("%s: события %v, ждали %v", id, f.events, want)
		}
	}
}

func TestSeenKeepsValue(t *testing.T) {
	st := around(map[string]hostcaps.Answer{"surroundings.dhcp_lan": hostcaps.Yes})
	st.Facts[0].Value = "192.168.1.1"
	f := &fakeSync{st: st}
	_ = f.sync().Step()
	if got := parseSeen(f.stored)["surroundings.dhcp_lan"]; got.Value != "192.168.1.1" || got.At == "" {
		t.Fatalf("отметка: %+v", got)
	}
}
