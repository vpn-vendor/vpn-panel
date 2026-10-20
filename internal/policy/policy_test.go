package policy

import "testing"

func TestParseValid(t *testing.T) {
	doc := []byte(`{
		"schema": 1,
		"flags": {"qos-off": true, "updates-pause": false},
		"advisory": {"pull_now": true, "message": "известная проблема, тянем исправление"},
		"known_bad": ["0.3.4", "0.3.5"]
	}`)
	p, warn, err := Parse(doc)
	if err != nil {
		t.Fatalf("годный документ не разобран: %v", err)
	}
	if len(warn) != 0 {
		t.Errorf("лишние замечания на годном документе: %v", warn)
	}
	if !p.Bool("qos-off") {
		t.Error("qos-off должен быть включён (true)")
	}
	if p.Bool("updates-pause") {
		t.Error("updates-pause должен быть false")
	}
	if !p.Advisory().PullNow || p.Advisory().Message == "" {
		t.Error("advisory не дошла")
	}
	if len(p.KnownBad()) != 2 {
		t.Errorf("список плохих версий: %v", p.KnownBad())
	}
}

func TestUnknownFlagSkipped(t *testing.T) {
	doc := []byte(`{"schema":1,"flags":{"qos-off":true,"флаг-из-будущего":true}}`)
	p, warn, err := Parse(doc)
	if err != nil {
		t.Fatalf("ошибка вместо пропуска: %v", err)
	}
	if !p.Bool("qos-off") {
		t.Error("известный флаг рядом с неизвестным не применился")
	}
	if len(warn) != 1 {
		t.Errorf("ждём одно замечание о неизвестном флаге, получили: %v", warn)
	}
}

func TestBadValueSkipped(t *testing.T) {
	doc := []byte(`{"schema":1,"flags":{"qos-off":"да","updates-pause":true}}`)
	p, warn, err := Parse(doc)
	if err != nil {
		t.Fatalf("ошибка вместо пропуска значения: %v", err)
	}
	if p.Bool("qos-off") {
		t.Error("негодное значение не должно было примениться")
	}
	if !p.Bool("updates-pause") {
		t.Error("годный соседний флаг не применился")
	}
	if len(warn) != 1 {
		t.Errorf("ждём замечание о негодном значении, получили: %v", warn)
	}
}

func TestBadSchema(t *testing.T) {
	p, _, err := Parse([]byte(`{"schema":99,"flags":{"qos-off":true}}`))
	if err == nil {
		t.Fatal("чужая версия формата принята")
	}
	if p.Bool("qos-off") {
		t.Error("при ошибке должна вернуться безопасная политика (все флаги выключены)")
	}
}

func TestBrokenDoc(t *testing.T) {
	p, _, err := Parse([]byte(`не json`))
	if err == nil {
		t.Fatal("мусор принят как документ")
	}
	if p.Bool("qos-off") {
		t.Error("безопасная политика при мусоре")
	}
}

func TestDefaultSafe(t *testing.T) {
	d := Default()
	for _, f := range Registry() {
		if d.Bool(f.Name) {
			t.Errorf("флаг %q по умолчанию не безопасен", f.Name)
		}
	}
	if d.Bool("чего-нет") {
		t.Error("неизвестный флаг должен читаться как false")
	}
}

func TestRegistrySound(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Registry() {
		if f.Name == "" {
			t.Error("флаг без имени")
		}
		if f.Why == "" {
			t.Errorf("флаг %q без пояснения", f.Name)
		}
		if seen[f.Name] {
			t.Errorf("повтор имени флага: %q", f.Name)
		}
		seen[f.Name] = true
	}
}

func TestParseVersionBounds(t *testing.T) {
	p, _, err := Parse([]byte(`{"schema":1,"ceiling":"0.3.4","floor":"0.3.2","known_bad":["0.3.3"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Ceiling() != "0.3.4" || p.Floor() != "0.3.2" {
		t.Errorf("границы версий не разобраны: ceiling=%q floor=%q", p.Ceiling(), p.Floor())
	}
	if len(p.KnownBad()) != 1 || p.KnownBad()[0] != "0.3.3" {
		t.Errorf("список плохих версий не разобран: %v", p.KnownBad())
	}
	empty, _, _ := Parse([]byte(`{"schema":1}`))
	if empty.Ceiling() != "" || empty.Floor() != "" {
		t.Error("без полей границы должны быть пусты (fail-safe)")
	}
}
