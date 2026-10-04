package backup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

var (
	fakeKeys = []settings.Key{
		{Name: "a.safe", Section: "a", Data: settings.Policy, Risk: settings.Safe},
		{Name: "a.notable", Section: "a", Data: settings.Policy, Risk: settings.Notable},
		{Name: "a.danger", Section: "a", Data: settings.Policy, Risk: settings.Dangerous, Title: "Опасное А", Warn: "грозит А"},
		{Name: "a.office", Section: "a", Data: settings.Office, Risk: settings.Safe},
		{Name: "a.state", Section: "a", Data: settings.State, Risk: settings.Safe},
		{Name: "b.src.", Prefix: true, Section: "b", Data: settings.Policy, Risk: settings.Safe},
		{Name: "b.item.", Prefix: true, Owner: settings.OwnerMetricsSource, Section: "b", Data: settings.Policy, Risk: settings.Safe},
		{Name: "b.itemdanger.", Prefix: true, Owner: settings.OwnerMetricsSource, Section: "b", Data: settings.Policy, Risk: settings.Dangerous},
	}
	fakeTables = []settings.Table{
		{Name: "settings", Section: "a", Data: settings.Policy, Risk: settings.Safe},
		{Name: "rows", Section: "b", Data: settings.Office, Risk: settings.Notable},
		{Name: "log", Section: "b", Data: settings.State, Risk: settings.Safe},
		{Name: "items", Section: "b", Data: settings.Policy, Risk: settings.Safe, Owner: settings.OwnerMetricsSource},
	}
)

type sectionA struct {
	Safe    int    `json:"safe" setting:"a.safe"`
	Notable bool   `json:"notable" setting:"a.notable"`
	Danger  string `json:"danger" setting:"a.danger"`
	Office  string `json:"office" setting:"a.office"`
}

type row struct {
	NIC   string `json:"nic" ref:"nic"`
	Label string `json:"label"`
}

type item struct {
	ID     string `json:"id" owner:"id"`
	Note   string `json:"note" setting:"b.item."`
	Danger string `json:"danger" setting:"b.itemdanger."`
}

type sectionB struct {
	Sources map[string]string `json:"sources" setting:"b.src."`
	Rows    []row             `json:"rows" table:"rows"`
	Items   []item            `json:"items" table:"items"`
}

func fakeEntries() []Entry {
	return []Entry{
		Of(Def[sectionB]{Name: "b", Version: 1, After: []settings.Section{"a"}, Validate: func(sectionB, Desired) fielderr.List { return nil },
			Apply: func(sectionB, sectionB, string) error { return nil },
			Read: func() (sectionB, error) {
				return sectionB{Sources: map[string]string{"cpu": "on"}, Rows: []row{{NIC: "ens3", Label: "касса"}},
					Items: []item{{ID: "cpu", Note: "заметка", Danger: "опасно"}}}, nil
			}}),
		Of(Def[sectionA]{Name: "a", Version: 1, Validate: func(sectionA, Desired) fielderr.List { return nil },
			Apply: func(sectionA, sectionA, string) error { return nil },
			Read: func() (sectionA, error) {
				return sectionA{Safe: 1, Notable: true, Danger: "direct", Office: "офис"}, nil
			}}),
	}
}

func withFakeRegistry(t *testing.T) {
	t.Helper()
	k, tb := registryKeys, registryTables
	registryKeys, registryTables = fakeKeys, fakeTables
	t.Cleanup(func() { registryKeys, registryTables = k, tb })
}

func TestCheckAcceptsFake(t *testing.T) {
	if errs := Check(fakeEntries(), fakeKeys, fakeTables); len(errs) > 0 {
		t.Fatal(errs)
	}
}

func TestCheckRejects(t *testing.T) {
	type noTag struct {
		X int `json:"x"`
	}
	type twoTags struct {
		X int `json:"x" setting:"a.safe" table:"rows"`
	}
	type undeclared struct {
		X int `json:"x" setting:"a.nope"`
	}
	type prefixNotMap struct {
		X string `json:"x" setting:"b.src."`
	}
	type tableNotSlice struct {
		X row `json:"x" table:"rows"`
	}
	type badRef struct {
		X []struct {
			N string `json:"n" ref:"disk"`
		} `json:"x" table:"rows"`
	}
	type stateField struct {
		X string `json:"x" setting:"a.state"`
	}
	type optional struct {
		X int `json:"x,omitempty" setting:"a.safe"`
	}
	type optionalRow struct {
		X []struct {
			N string `json:"n,omitempty"`
		} `json:"x" table:"rows"`
	}
	type foreignSection struct {
		X []row `json:"x" table:"rows"`
	}
	type ownedAsMap struct {
		X map[string]string `json:"x" setting:"b.item."`
	}
	type rowWithoutID struct {
		X []struct {
			N string `json:"n" setting:"b.item."`
		} `json:"x" table:"items"`
	}
	type ownedInForeignRow struct {
		X []struct {
			ID string `json:"id" owner:"id"`
			N  string `json:"n" setting:"b.item."`
		} `json:"x" table:"rows"`
	}
	type rowSettingNotString struct {
		X []struct {
			ID string `json:"id" owner:"id"`
			N  int    `json:"n" setting:"b.item."`
		} `json:"x" table:"items"`
	}
	type badOwnerTag struct {
		X []struct {
			ID string `json:"id" owner:"slug"`
			N  string `json:"n" setting:"b.item."`
		} `json:"x" table:"items"`
	}
	cases := map[string]struct {
		entries []Entry
		want    string
	}{
		"поле без метки":          {[]Entry{Of(Def[noTag]{Name: "a", Version: 1})}, "ровно одна метка"},
		"две метки":               {[]Entry{Of(Def[twoTags]{Name: "a", Version: 1})}, "ровно одна метка"},
		"ключ не объявлен":        {[]Entry{Of(Def[undeclared]{Name: "a", Version: 1})}, "не объявлен"},
		"хвост ключа не словарь":  {[]Entry{Of(Def[prefixNotMap]{Name: "b", Version: 1})}, "словарь"},
		"таблица не список":       {[]Entry{Of(Def[tableNotSlice]{Name: "b", Version: 1})}, "список строк"},
		"чужая ссылка на железо":  {[]Entry{Of(Def[badRef]{Name: "b", Version: 1})}, "ссылка на железо"},
		"состояние в копии":       {[]Entry{Of(Def[stateField]{Name: "a", Version: 1})}, "не переносится"},
		"необязательное поле":     {[]Entry{Of(Def[optional]{Name: "a", Version: 1})}, "нет необязательности"},
		"необязательное в строке": {[]Entry{Of(Def[optionalRow]{Name: "b", Version: 1})}, "нет необязательности"},
		"поле чужого раздела":     {[]Entry{Of(Def[foreignSection]{Name: "a", Version: 1})}, "относится к разделу"},
		"ключ строки словарём":    {[]Entry{Of(Def[ownedAsMap]{Name: "b", Version: 1})}, "его место в поле строки"},
		"строка без хвоста":       {[]Entry{Of(Def[rowWithoutID]{Name: "b", Version: 1})}, `ровно одно поле owner:"id"`},
		"ключ в чужой строке":     {[]Entry{Of(Def[ownedInForeignRow]{Name: "b", Version: 1})}, "только ключи её владельца"},
		"настройка строки числом": {[]Entry{Of(Def[rowSettingNotString]{Name: "b", Version: 1})}, "одно значение, строка"},
		"неверная метка хвоста":   {[]Entry{Of(Def[badOwnerTag]{Name: "b", Version: 1})}, "метка owner бывает"},
		"настройка без поля":      {fakeEntries()[1:], "нет поля раздела"},
		"раздел дважды":           {append(fakeEntries(), fakeEntries()[1]), "дважды"},
		"версия ноль":             {[]Entry{Of(Def[sectionA]{Name: "a"}), fakeEntries()[0]}, "версия меньше 1"},
		"неизвестная зависимость": {[]Entry{Of(Def[sectionA]{Name: "a", Version: 1, After: []settings.Section{"z"}}), fakeEntries()[0]}, "неизвестного раздела"},
		"раздел без проверки":     {[]Entry{Of(Def[sectionA]{Name: "a", Version: 1}), fakeEntries()[0]}, "нет проверки"},
		"раздел без применения": {[]Entry{Of(Def[sectionA]{Name: "a", Version: 1,
			Validate: func(sectionA, Desired) fielderr.List { return nil }}), fakeEntries()[0]}, "нет применения"},
		"цикл зависимостей": {[]Entry{Of(Def[sectionA]{Name: "a", Version: 1, After: []settings.Section{"b"}}), fakeEntries()[0]}, "цикл"},
	}
	for name, c := range cases {
		errs := Check(c.entries, fakeKeys, fakeTables)
		if !strings.Contains(errors.Join(errs...).Error()+" ", c.want) {
			t.Errorf("%s: ждали «%s», получили %v", name, c.want, errs)
		}
	}
}

func TestOrderFollowsDependencies(t *testing.T) {
	got, err := Order(fakeEntries())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name() != "a" || got[1].Name() != "b" {
		t.Fatalf("порядок: %s, %s — «b» зависит от «a»", got[0].Name(), got[1].Name())
	}
}

func TestBuildTemplateLaw(t *testing.T) {
	withFakeRegistry(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	tpl, err := Build(fakeEntries(), backupfile.KindTemplate, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	a := string(tpl.Sections["a"].Data)
	for _, want := range []string{`"safe":1`, `"notable":true`} {
		if !strings.Contains(a, want) {
			t.Errorf("в шаблоне нет %s: %s", want, a)
		}
	}
	for _, banned := range []string{"danger", "office"} {
		if strings.Contains(a, banned) {
			t.Errorf("в шаблон попало %q: %s", banned, a)
		}
	}
	if b, ok := tpl.Sections["b"]; !ok || strings.Contains(string(b.Data), "rows") {
		t.Errorf("раздел «b»: строки офиса попали в шаблон или политика пропала: %s", b.Data)
	}
	b := string(tpl.Sections["b"].Data)
	if !strings.Contains(b, `"note":"заметка"`) || strings.Contains(b, "опасно") {
		t.Errorf("строки политики: безопасная настройка строки пропала или опасная попала в шаблон: %s", b)
	}
	cp, err := Build(fakeEntries(), backupfile.KindCopy, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"danger":"direct"`, `"office":"офис"`, `"label":"касса"`, `"danger":"опасно"`} {
		if !strings.Contains(string(cp.Sections["a"].Data)+string(cp.Sections["b"].Data), want) {
			t.Errorf("в копии нет %s", want)
		}
	}

	raw, _ := backupfile.Marshal(cp)
	if _, err := backupfile.Parse(raw); err != nil {
		t.Fatalf("собранная копия не разбирается: %v", err)
	}
}

func TestDangerousFields(t *testing.T) {
	withFakeRegistry(t)
	got, err := Dangerous(fakeEntries()[1])
	if err != nil || len(got) != 1 || got[0].JSON != "danger" {
		t.Fatalf("опасные поля: %+v %v", got, err)
	}
	got, err = Dangerous(fakeEntries()[0])
	if err != nil || len(got) != 1 || got[0].JSON != "items[].danger" {
		t.Fatalf("опасные поля строк: %+v %v", got, err)
	}
}

func TestDecodeStrict(t *testing.T) {
	e := fakeEntries()[1]
	if _, err := e.Decode(json.RawMessage(`{"safe":1,"run":"x"}`)); !errors.Is(err, backupfile.ErrMalformed) {
		t.Fatalf("неизвестное поле раздела: %v", err)
	}
	if _, err := e.Decode(json.RawMessage(`{"safe":1}{}`)); !errors.Is(err, backupfile.ErrMalformed) {
		t.Fatalf("хвост после раздела: %v", err)
	}
	if _, err := e.Decode(json.RawMessage(`{"safe":1,"notable":false}`)); err != nil {
		t.Fatalf("контроль: годный раздел отвергнут: %v", err)
	}
}
