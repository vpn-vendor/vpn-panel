package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

func TestSectionsComplete(t *testing.T) {
	if errs := Check(Sections(), settings.Keys, settings.Tables); len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
	}

	var without []Entry
	for _, e := range Sections() {
		if e.Name() != settings.SectionVPN {
			without = append(without, e)
		}
	}
	joined := ""
	for _, e := range Check(without, settings.Keys, settings.Tables) {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{`"vpn.mode"`, `"vpn_profiles"`, `"vpn.probe_target."`} {
		if !strings.Contains(joined, want) {
			t.Errorf("страж не назвал непокрытое %s:\n%s", want, joined)
		}
	}
}

func TestSectionsShape(t *testing.T) {
	for _, e := range ShapeErrors(Sections(), "testdata/golden") {
		t.Error(e)
	}
}

func TestShapeCatchesNewField(t *testing.T) {
	type qosPlus struct {
		qos.Section
		Extra int `json:"extra"`
	}
	grown := Of(Def[qosPlus]{Name: settings.SectionQoS, Version: 1})
	errs := ShapeErrors([]Entry{grown}, "testdata/golden")
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "форма изменилась") {
		t.Fatalf("добавленное поле без новой версии не замечено: %v", errs)
	}
	type qosLess struct {
		Enabled bool `json:"enabled" setting:"qos.enabled"`
	}
	shrunk := Of(Def[qosLess]{Name: settings.SectionQoS, Version: 1})
	if errs := ShapeErrors([]Entry{shrunk}, "testdata/golden"); len(errs) == 0 {
		t.Fatal("убранное поле без новой версии не замечено")
	}
	if reflect.TypeFor[qosPlus]().NumField() != 2 {
		t.Fatal("контроль собран неверно")
	}
}

func TestGoldenPassesValidation(t *testing.T) {
	ordered, err := Order(Sections())
	if err != nil {
		t.Fatal(err)
	}
	d := Desired{}
	for _, e := range ordered {
		raw, err := os.ReadFile(filepath.Join("testdata/golden", string(e.Name()), fmt.Sprintf("v%d.json", e.Spec().Version)))
		if err != nil {
			t.Fatal(err)
		}
		v, err := e.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if errs := e.Validate(v, d); len(errs) > 0 {
			t.Errorf("эталон раздела %q не прошёл проверку: %v", e.Name(), errs.Err())
		}
		d[e.Name()] = v
	}
}

func TestSectionsOrder(t *testing.T) {
	got, err := Order(Sections())
	if err != nil {
		t.Fatal(err)
	}
	pos := map[settings.Section]int{}
	for i, e := range got {
		pos[e.Name()] = i
	}
	for _, e := range got {
		for _, dep := range e.After() {
			if pos[dep] > pos[e.Name()] {
				t.Errorf("раздел %q применяется раньше своей зависимости %q", e.Name(), dep)
			}
		}
	}
	if pos[settings.SectionNetwork] != 0 {
		t.Error("сеть обязана применяться первой")
	}
}

func TestLateSourcesKnown(t *testing.T) {
	if !slices.Contains(metrics.SourceNames(), pathmon.SourceName) {
		t.Fatalf("источник %q неизвестен проверке раздела: %v", pathmon.SourceName, metrics.SourceNames())
	}
	v := metrics.Section{Master: "on", Sources: map[string]string{pathmon.SourceName: "off"}}
	if errs := metrics.ValidateSection(v); len(errs) > 0 {
		t.Fatalf("состояние пробы пути отвергнуто: %v", errs.Err())
	}
}
