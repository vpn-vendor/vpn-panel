package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

var ErrDangerousInTemplate = errors.New("в шаблоне опасная настройка — такой файл не принимается; её возвращает только своя копия")

const (
	Changed = "changed"
	Added   = "added"
	Removed = "removed"
)

type Change struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Dangerous bool   `json:"dangerous"`

	Item string `json:"item,omitempty"`

	Title string `json:"title,omitempty"`
	Warn  string `json:"warn,omitempty"`
}

type SectionPlan struct {
	Name settings.Section `json:"name"`

	InFile bool `json:"in_file"`

	Changes []Change `json:"changes"`

	NotTransferred []string `json:"not_transferred"`
}

type Plan struct {
	Kind     backupfile.Kind `json:"kind"`
	Sections []SectionPlan   `json:"sections"`
	Errors   []string        `json:"errors"`

	order   []Entry
	current Desired
	desired Desired
}

func (p *Plan) Ready() bool { return len(p.Errors) == 0 }

func (p *Plan) Dangerous() []Change {
	var out []Change
	for _, s := range p.Sections {
		for _, c := range s.Changes {
			if c.Dangerous {
				c.Path = string(s.Name) + "." + c.Path
				out = append(out, c)
			}
		}
	}
	return out
}

func Prepare(entries []Entry, doc *backupfile.Document) (*Plan, error) {
	order, err := Order(entries)
	if err != nil {
		return nil, err
	}
	if err := Specs(entries).Migrate(doc); err != nil {
		return nil, err
	}
	plan := &Plan{Kind: doc.Kind, order: order, current: Desired{}, desired: Desired{}}
	for _, e := range order {
		name := e.Name()
		curRaw, err := e.Export()
		if err != nil {
			return nil, fmt.Errorf("раздел %q: %w", name, err)
		}
		cur, err := e.Decode(curRaw)
		if err != nil {
			return nil, fmt.Errorf("раздел %q: текущие данные: %w", name, err)
		}
		plan.current[name] = cur
		sp := SectionPlan{Name: name, NotTransferred: notTransferred(name)}
		sec, inFile := doc.Sections[string(name)]
		if !inFile {
			plan.desired[name] = cur
			plan.Sections = append(plan.Sections, sp)
			continue
		}
		sp.InFile = true
		wantRaw := sec.Data
		if doc.Kind == backupfile.KindTemplate {
			if err := refuseDangerous(e, sec.Data); err != nil {
				return nil, err
			}
			if wantRaw, err = overlay(curRaw, sec.Data); err != nil {
				return nil, fmt.Errorf("раздел %q: %w", name, err)
			}
		}
		want, err := e.Decode(wantRaw)
		if err != nil {
			return nil, fmt.Errorf("раздел %q: %w", name, err)
		}
		for _, fe := range e.Validate(want, plan.desired) {
			plan.Errors = append(plan.Errors, string(name)+"."+fe.Error())
		}
		plan.desired[name] = want
		if sp.Changes, err = diff(e, curRaw, wantRaw); err != nil {
			return nil, fmt.Errorf("раздел %q: %w", name, err)
		}
		plan.Sections = append(plan.Sections, sp)
	}
	return plan, nil
}

func (p *Plan) Write(ip string) error {
	if !p.Ready() {
		return fmt.Errorf("план не прошёл проверку: %s", strings.Join(p.Errors, "; "))
	}
	for i, e := range p.order {
		sp := p.Sections[i]
		if !sp.InFile || len(sp.Changes) == 0 {
			continue
		}
		if err := e.Apply(p.current[sp.Name], p.desired[sp.Name], ip); err != nil {
			return fmt.Errorf("раздел %q: %w", sp.Name, err)
		}
	}
	return nil
}

func notTransferred(name settings.Section) []string {
	var out []string
	for _, k := range registryKeys {
		if k.Section == name && !k.Data.InCopy() {
			out = append(out, k.Name)
		}
	}
	for _, t := range registryTables {
		if t.Section == name && !t.Data.InCopy() {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

func refuseDangerous(e Entry, data json.RawMessage) error {
	fields, err := Dangerous(e)
	if err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	for _, f := range fields {
		table, sub, isRow := strings.Cut(f.JSON, "[].")
		if !isRow {
			if _, ok := obj[f.JSON]; ok {
				return fmt.Errorf("%w (%s.%s)", ErrDangerousInTemplate, e.Name(), f.JSON)
			}
			continue
		}
		var rows []map[string]json.RawMessage
		if raw, ok := obj[table]; ok && json.Unmarshal(raw, &rows) == nil {
			for _, r := range rows {
				if _, ok := r[sub]; ok {
					return fmt.Errorf("%w (%s.%s)", ErrDangerousInTemplate, e.Name(), f.JSON)
				}
			}
		}
	}
	return nil
}

func overlay(cur, tmpl json.RawMessage) (json.RawMessage, error) {
	var base, over map[string]json.RawMessage
	if err := json.Unmarshal(cur, &base); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(tmpl, &over); err != nil {
		return nil, err
	}
	for k, v := range over {
		base[k] = v
	}
	return json.Marshal(base)
}

func diff(e Entry, cur, want json.RawMessage) ([]Change, error) {
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(cur, &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(want, &b); err != nil {
		return nil, err
	}
	fields, err := classes(e)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(b))
	for k := range b {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Change
	for _, k := range keys {
		if sameJSON(a[k], b[k]) {
			continue
		}
		f := fields[k]
		if f.Table == "" {
			out = append(out, Change{Path: k, Kind: Changed, Dangerous: f.Risk == settings.Dangerous, Title: f.Title, Warn: f.Warn})
			continue
		}
		out = append(out, rowChanges(k, rowKey(e.Shape(), k), f, a[k], b[k])...)
	}
	return out, nil
}

func classes(e Entry) (map[string]Field, error) {
	fields, errs := Fields(e.Shape(), registryKeys, registryTables)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	out := map[string]Field{}
	for _, f := range fields {
		out[f.JSON] = f
	}
	return out, nil
}

func rowChanges(table, key string, f Field, cur, want json.RawMessage) []Change {
	var a, b []map[string]json.RawMessage
	_ = json.Unmarshal(cur, &a)
	_ = json.Unmarshal(want, &b)
	id := func(r map[string]json.RawMessage) string {
		if key != "" {
			var s string
			if json.Unmarshal(r[key], &s) == nil {
				return s
			}
		}
		raw, _ := json.Marshal(r)
		return string(raw)
	}

	change := func(item, kind string, x, y map[string]json.RawMessage) Change {
		c := Change{Path: table + "[" + item + "]", Kind: kind, Item: item}
		if f.Risk == settings.Dangerous {
			c.Dangerous, c.Title, c.Warn = true, f.Title, f.Warn
			return c
		}
		for _, r := range f.Rows {
			if r.Risk == settings.Dangerous && (x == nil || y == nil || !sameJSON(x[r.JSON], y[r.JSON])) {
				c.Dangerous, c.Title, c.Warn = true, r.Title, r.Warn
				return c
			}
		}
		return c
	}
	byID := map[string]map[string]json.RawMessage{}
	for _, r := range a {
		byID[id(r)] = r
	}
	var out []Change
	seen := map[string]bool{}
	for _, r := range b {
		k := id(r)
		seen[k] = true
		old, ok := byID[k]
		switch {
		case !ok:
			out = append(out, change(label(k, key), Added, nil, r))
		case !sameJSON(mustJSON(old), mustJSON(r)):
			out = append(out, change(label(k, key), Changed, old, r))
		}
	}
	for _, r := range a {
		if k := id(r); !seen[k] {
			out = append(out, change(label(k, key), Removed, r, nil))
		}
	}
	return out
}

func label(id, key string) string {
	if key == "" {
		return "строка"
	}
	return id
}

func rowKey(shape reflect.Type, jsonName string) string {
	for i := 0; i < shape.NumField(); i++ {
		sf := shape.Field(i)
		if strings.Split(sf.Tag.Get("json"), ",")[0] != jsonName || sf.Type.Kind() != reflect.Slice {
			continue
		}
		row := sf.Type.Elem()
		for j := 0; j < row.NumField(); j++ {
			if row.Field(j).Tag.Get("owner") == "id" {
				return strings.Split(row.Field(j).Tag.Get("json"), ",")[0]
			}
		}
	}
	return ""
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
