package backupfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func doc(kind Kind) *Document {
	return &Document{
		Format: FormatName, FormatVersion: FormatVersion, Kind: kind,
		PanelVersion: "0.3.0", CreatedAt: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC),
		Sections: map[string]Section{"qos": {Version: 1, Data: json.RawMessage(`{"down_kbit":1000}`)}},
	}
}

func TestRoundTrip(t *testing.T) {
	raw, err := Marshal(doc(KindCopy))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindCopy || got.Sections["qos"].Version != 1 {
		t.Fatalf("прочитано другое: %+v", got)
	}
}

func TestParseStrict(t *testing.T) {
	good, _ := Marshal(doc(KindTemplate))
	for _, c := range []struct {
		name string
		raw  string
		want error
	}{
		{"неизвестное поле", strings.Replace(string(good), `"kind"`, `"run":"x","kind"`, 1), ErrMalformed},
		{"лишние данные после документа", string(good) + `{}`, ErrMalformed},
		{"чужая метка формата", strings.Replace(string(good), FormatName, "other-format", 1), ErrMalformed},
		{"версия формата новее", strings.Replace(string(good), `"format_version": 1`, `"format_version": 99`, 1), ErrNewer},
		{"неизвестный вид файла", strings.Replace(string(good), `"template"`, `"script"`, 1), ErrMalformed},
		{"шаблон с секретами", strings.Replace(string(good), `"sections"`, `"secrets":{"k":"v"},"sections"`, 1), ErrTemplateSecrets},
		{"раздел без версии", strings.Replace(string(good), `"version": 1`, `"version": 0`, 1), ErrMalformed},
		{"не JSON", "PostUp = rm -rf /", ErrMalformed},
		{"слишком большой", `{"format":"` + strings.Repeat("x", MaxBytes) + `"}`, ErrTooLarge},
	} {
		_, err := Parse([]byte(c.raw))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, ждали %v", c.name, err, c.want)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("контроль: годный шаблон отвергнут: %v", err)
	}
	withSecrets := doc(KindTemplate)
	withSecrets.Secrets = json.RawMessage(`{"k":"v"}`)
	if _, err := Marshal(withSecrets); !errors.Is(err, ErrTemplateSecrets) {
		t.Fatal("шаблон с секретами записан")
	}
}

func demoSpec() Spec {
	return Spec{Version: 3, Up: map[int]func(json.RawMessage) (json.RawMessage, error){
		1: func(d json.RawMessage) (json.RawMessage, error) {
			var v1 struct {
				Speed int `json:"speed_kbit"`
			}
			if err := json.Unmarshal(d, &v1); err != nil {
				return nil, err
			}
			return json.Marshal(map[string]int{"down_kbit": v1.Speed})
		},
		2: func(d json.RawMessage) (json.RawMessage, error) {
			var v2 map[string]any
			if err := json.Unmarshal(d, &v2); err != nil {
				return nil, err
			}
			v2["enabled"] = true
			return json.Marshal(v2)
		},
	}}
}

func TestMigrate(t *testing.T) {
	d := &Document{Sections: map[string]Section{"demo": {Version: 1, Data: json.RawMessage(`{"speed_kbit":5}`)}}}
	if err := (Specs{"demo": demoSpec()}).Migrate(d); err != nil {
		t.Fatal(err)
	}
	if s := d.Sections["demo"]; s.Version != 3 || !bytes.Contains(s.Data, []byte(`"down_kbit":5`)) ||
		!bytes.Contains(s.Data, []byte(`"enabled":true`)) {
		t.Fatalf("миграция дала %d %s", s.Version, s.Data)
	}
	newer := &Document{Sections: map[string]Section{"demo": {Version: 4, Data: json.RawMessage(`{}`)}}}
	if err := (Specs{"demo": demoSpec()}).Migrate(newer); !errors.Is(err, ErrNewer) {
		t.Fatalf("раздел новее панели: %v", err)
	}
	unknown := &Document{Sections: map[string]Section{"future": {Version: 1, Data: json.RawMessage(`{}`)}}}
	if err := (Specs{"demo": demoSpec()}).Migrate(unknown); !errors.Is(err, ErrUnknownSection) {
		t.Fatalf("неизвестный раздел: %v", err)
	}
}

func TestSpecsValidate(t *testing.T) {
	if errs := (Specs{"demo": demoSpec()}).Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	gap := demoSpec()
	delete(gap.Up, 2)
	if errs := (Specs{"demo": gap}).Validate(); len(errs) == 0 {
		t.Fatal("пропуск шага миграции не замечен")
	}
	extra := demoSpec()
	extra.Up[3] = extra.Up[2]
	if errs := (Specs{"demo": extra}).Validate(); len(errs) == 0 {
		t.Fatal("лишний шаг миграции не замечен")
	}
}

func TestGolden(t *testing.T) {
	if errs := GoldenErrors(Specs{"demo": demoSpec()}, "testdata/golden"); len(errs) > 0 {
		t.Fatal(errs)
	}

	broken := demoSpec()
	broken.Up[2] = func(d json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"down_kbit":1000,"enabled":false}`), nil
	}
	if errs := GoldenErrors(Specs{"demo": broken}, "testdata/golden"); len(errs) == 0 {
		t.Fatal("испорченная миграция прошла эталон")
	}

	ahead := demoSpec()
	ahead.Version = 4
	ahead.Up[3] = ahead.Up[2]
	if errs := GoldenErrors(Specs{"demo": ahead}, "testdata/golden"); len(errs) == 0 {
		t.Fatal("версия без эталона прошла")
	}
}
