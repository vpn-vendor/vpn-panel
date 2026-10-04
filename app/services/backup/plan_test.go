package backup

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

func buildDoc(t *testing.T, entries []Entry, kind backupfile.Kind) *backupfile.Document {
	t.Helper()
	doc, err := Build(entries, kind, "0", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func edit(t *testing.T, doc *backupfile.Document, name string, f func(map[string]any)) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(doc.Sections[name].Data, &obj); err != nil {
		t.Fatal(err)
	}
	f(obj)
	raw, _ := json.Marshal(obj)
	s := doc.Sections[name]
	s.Data = raw
	doc.Sections[name] = s
}

func section(p *Plan, name settings.Section) SectionPlan {
	for _, s := range p.Sections {
		if s.Name == name {
			return s
		}
	}
	return SectionPlan{}
}

func TestOwnCopyChangesNothing(t *testing.T) {
	withFakeRegistry(t)
	p, err := Prepare(fakeEntries(), buildDoc(t, fakeEntries(), backupfile.KindCopy))
	if err != nil || !p.Ready() {
		t.Fatalf("%v %v", err, p.Errors)
	}
	if len(p.Sections) != 2 || p.Sections[0].Name != "a" || p.Sections[1].Name != "b" {
		t.Fatalf("порядок применения: %+v", p.Sections)
	}
	for _, s := range p.Sections {
		if !s.InFile || len(s.Changes) != 0 {
			t.Errorf("%s: своя копия без правок меняет %+v", s.Name, s.Changes)
		}
	}
	if nt := section(p, "a").NotTransferred; len(nt) != 1 || nt[0] != "a.state" {
		t.Fatalf("«не переносится» из реестра: %v", nt)
	}
	if nt := section(p, "b").NotTransferred; len(nt) != 1 || nt[0] != "log" {
		t.Fatalf("таблица состояния не переносится: %v", nt)
	}
}

func TestChangesAreListedAndDangerMarked(t *testing.T) {
	withFakeRegistry(t)
	doc := buildDoc(t, fakeEntries(), backupfile.KindCopy)
	edit(t, doc, "a", func(o map[string]any) { o["safe"], o["danger"] = 5, "strict" })
	edit(t, doc, "b", func(o map[string]any) {
		o["items"] = []map[string]any{{"id": "cpu", "note": "заметка", "danger": "иначе"}, {"id": "mem", "note": "", "danger": ""}}
		o["rows"] = []map[string]any{{"nic": "ens3", "label": "касса"}, {"nic": "ens4", "label": "склад"}}
	})
	p, err := Prepare(fakeEntries(), doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, s := range p.Sections {
		for _, c := range s.Changes {
			got[string(s.Name)+"."+c.Path] = c
		}
	}
	for path, want := range map[string]Change{
		"a.safe":         {Kind: Changed},
		"a.danger":       {Kind: Changed, Dangerous: true},
		"b.items[cpu]":   {Kind: Changed, Dangerous: true},
		"b.items[mem]":   {Kind: Added, Dangerous: true},
		"b.rows[строка]": {Kind: Added},
	} {
		c, ok := got[path]
		if !ok || c.Kind != want.Kind || c.Dangerous != want.Dangerous {
			t.Errorf("%s: %+v (ждали %+v); весь план %v", path, c, want, got)
		}
	}
	if len(p.Dangerous()) != 3 {
		t.Fatalf("опасные строки плана: %v", p.Dangerous())
	}
}

func TestAbsentSectionIsLeftAlone(t *testing.T) {
	withFakeRegistry(t)
	doc := buildDoc(t, fakeEntries(), backupfile.KindCopy)
	delete(doc.Sections, "b")
	p, err := Prepare(fakeEntries(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if s := section(p, "b"); s.InFile || len(s.Changes) != 0 || p.desired["b"] == nil {
		t.Fatalf("раздела нет в файле — не трогается: %+v", s)
	}
}

func TestTemplateOverlaysAndRefusesDanger(t *testing.T) {
	withFakeRegistry(t)
	doc := buildDoc(t, fakeEntries(), backupfile.KindTemplate)
	edit(t, doc, "a", func(o map[string]any) { o["safe"] = 7 })
	p, err := Prepare(fakeEntries(), doc)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := DesiredOf[sectionA](p.desired, "a")
	if a.Safe != 7 || a.Office != "офис" || a.Danger != "direct" {
		t.Fatalf("шаблон накладывается только своими полями: %+v", a)
	}
	bad := buildDoc(t, fakeEntries(), backupfile.KindTemplate)
	edit(t, bad, "a", func(o map[string]any) { o["danger"] = "direct" })
	if _, err := Prepare(fakeEntries(), bad); !errors.Is(err, ErrDangerousInTemplate) {
		t.Fatalf("опасное поле в шаблоне: %v", err)
	}
	bad = buildDoc(t, fakeEntries(), backupfile.KindTemplate)
	edit(t, bad, "b", func(o map[string]any) { o["items"] = []map[string]any{{"id": "cpu", "note": "x", "danger": "y"}} })
	if _, err := Prepare(fakeEntries(), bad); !errors.Is(err, ErrDangerousInTemplate) {
		t.Fatalf("опасное поле строки в шаблоне: %v", err)
	}
}

func TestValidationSeesDesiredAncestors(t *testing.T) {
	withFakeRegistry(t)
	entries := fakeEntries()
	entries[0] = Of(Def[sectionB]{Name: "b", Version: 1, After: []settings.Section{"a"},
		Validate: func(v sectionB, d Desired) fielderr.List {
			var errs fielderr.List
			if a, ok := DesiredOf[sectionA](d, "a"); !ok || a.Safe != 9 {
				errs.Add("sources", "предок не виден: %+v", a)
			}
			return errs
		},
		Apply: func(sectionB, sectionB, string) error { return nil },
		Read:  func() (sectionB, error) { return sectionB{}, nil }})
	doc := buildDoc(t, entries, backupfile.KindCopy)
	edit(t, doc, "a", func(o map[string]any) { o["safe"] = 9 })
	p, err := Prepare(entries, doc)
	if err != nil || !p.Ready() {
		t.Fatalf("%v %v", err, p.Errors)
	}
	edit(t, doc, "a", func(o map[string]any) { o["safe"] = 1 })
	if p, _ = Prepare(entries, doc); p.Ready() || p.Errors[0][:2] != "b." {
		t.Fatalf("ошибка раздела с его именем: %v", p.Errors)
	}
}

func TestUnknownSectionRefused(t *testing.T) {
	withFakeRegistry(t)
	doc := buildDoc(t, fakeEntries(), backupfile.KindCopy)
	doc.Sections["z"] = backupfile.Section{Version: 1, Data: json.RawMessage(`{}`)}
	if _, err := Prepare(fakeEntries(), doc); !errors.Is(err, backupfile.ErrUnknownSection) {
		t.Fatalf("незнакомый раздел: %v", err)
	}
}

func TestDangerousTableMarksEveryRowWithItsWords(t *testing.T) {
	withFakeRegistry(t)
	tables := append([]settings.Table(nil), fakeTables...)
	for i := range tables {
		if tables[i].Name == "rows" {
			tables[i].Risk, tables[i].Title, tables[i].Warn = settings.Dangerous, "Карты", "отрежет офис"
		}
	}
	registryTables = tables
	doc := buildDoc(t, fakeEntries(), backupfile.KindCopy)
	edit(t, doc, "a", func(o map[string]any) { o["danger"] = "strict" })
	edit(t, doc, "b", func(o map[string]any) {
		o["rows"] = []map[string]any{{"nic": "ens3", "label": "склад"}}
	})
	p, err := Prepare(fakeEntries(), doc)
	if err != nil {
		t.Fatal(err)
	}
	var rows, field bool
	for _, c := range p.Dangerous() {
		switch {
		case c.Title == "Карты" && c.Warn == "отрежет офис" && c.Item == "строка":
			rows = true
		case c.Path == "a.danger" && c.Title == "Опасное А" && c.Warn == "грозит А":
			field = true
		}
	}
	if !rows || !field {
		t.Fatalf("опасные строки со словами реестра: %+v", p.Dangerous())
	}
}
