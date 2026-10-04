package backup

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

type Card struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

type Ref struct {
	Section settings.Section
	Card    Card
	Row     map[string]json.RawMessage
}

func (r Ref) Field(name string) string {
	var s string
	if json.Unmarshal(r.Row[name], &s) == nil {
		return s
	}
	return strings.Trim(string(r.Row[name]), `"`)
}

type refCols struct{ nic, mac string }

func Refs(entries []Entry, doc *backupfile.Document) ([]Ref, error) {
	var out []Ref
	err := eachRef(entries, doc, func(name settings.Section, row map[string]json.RawMessage, cols refCols) bool {
		out = append(out, Ref{Section: name, Card: cardOf(row, cols), Row: row})
		return false
	})
	return out, err
}

func Remap(entries []Entry, doc *backupfile.Document, to map[string]Card) error {
	return eachRef(entries, doc, func(_ settings.Section, row map[string]json.RawMessage, cols refCols) bool {
		c, ok := to[cardOf(row, cols).Name]
		if !ok {
			return false
		}
		row[cols.nic] = mustJSON(c.Name)
		if cols.mac != "" {
			row[cols.mac] = mustJSON(c.MAC)
		}
		return true
	})
}

func Match(refs []Ref, here []Card) (auto map[string]Card, ask []Ref) {
	auto = map[string]Card{}
	byMAC := map[string]Card{}
	for _, c := range here {
		if c.MAC != "" {
			byMAC[strings.ToLower(c.MAC)] = c
		}
	}
	for _, r := range refs {
		if c, ok := byMAC[strings.ToLower(r.Card.MAC)]; ok && r.Card.MAC != "" {
			auto[r.Card.Name] = c
			continue
		}
		ask = append(ask, r)
	}
	return auto, ask
}

func Assign(refs []Ref, here []Card, choice map[string]string) (map[string]Card, []string) {
	auto, ask := Match(refs, here)
	byName := map[string]Card{}
	for _, c := range here {
		byName[c.Name] = c
	}
	taken := map[string]string{}
	for from, c := range auto {
		taken[c.Name] = from
	}
	var errs []string
	for _, r := range ask {
		want := choice[r.Card.Name]
		c, ok := byName[want]
		switch {
		case want == "":
			errs = append(errs, fmt.Sprintf("карта %q из файла не назначена карте этого шлюза", r.Card.Name))
			continue
		case !ok:
			errs = append(errs, fmt.Sprintf("карты %q на этом шлюзе нет", want))
			continue
		case taken[c.Name] != "":
			errs = append(errs, fmt.Sprintf("карта %q уже получила роль карты %q из файла", c.Name, taken[c.Name]))
			continue
		}
		taken[c.Name] = r.Card.Name
		auto[r.Card.Name] = c
	}
	return auto, errs
}

func cardOf(row map[string]json.RawMessage, cols refCols) Card {
	var c Card
	_ = json.Unmarshal(row[cols.nic], &c.Name)
	if cols.mac != "" {
		_ = json.Unmarshal(row[cols.mac], &c.MAC)
	}
	return c
}

func eachRef(entries []Entry, doc *backupfile.Document, visit func(settings.Section, map[string]json.RawMessage, refCols) bool) error {
	if err := Specs(entries).Migrate(doc); err != nil {
		return err
	}
	for _, e := range entries {
		sec, ok := doc.Sections[string(e.Name())]
		if !ok {
			continue
		}
		tables := refTables(e.Shape())
		if len(tables) == 0 {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(sec.Data, &obj); err != nil {
			return fmt.Errorf("раздел %q: %w", e.Name(), err)
		}
		changed := false
		for table, cols := range tables {
			var rows []map[string]json.RawMessage
			if len(obj[table]) == 0 || string(obj[table]) == "null" {
				continue
			}
			if err := json.Unmarshal(obj[table], &rows); err != nil {
				return fmt.Errorf("раздел %q: %w", e.Name(), err)
			}
			hit := false
			for _, row := range rows {
				hit = visit(e.Name(), row, cols) || hit
			}
			if hit {
				obj[table], changed = mustJSON(rows), true
			}
		}
		if changed {
			sec.Data = mustJSON(obj)
			doc.Sections[string(e.Name())] = sec
		}
	}
	return nil
}

func refTables(shape reflect.Type) map[string]refCols {
	out := map[string]refCols{}
	for i := range shape.NumField() {
		sf := shape.Field(i)
		if sf.Tag.Get("table") == "" || sf.Type.Kind() != reflect.Slice || sf.Type.Elem().Kind() != reflect.Struct {
			continue
		}
		var cols refCols
		row := sf.Type.Elem()
		for j := range row.NumField() {
			name, _, _ := strings.Cut(row.Field(j).Tag.Get("json"), ",")
			switch row.Field(j).Tag.Get("ref") {
			case "nic":
				cols.nic = name
			case "mac":
				cols.mac = name
			}
		}
		if cols.nic != "" {
			table, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
			out[table] = cols
		}
	}
	return out
}
