package backup

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

type Field struct {
	JSON    string
	Setting string
	Table   string
	Data    settings.Data
	Risk    settings.Risk

	Title, Warn string

	Rows []Field
}

var refKinds = map[string]bool{"nic": true, "mac": true}

func Fields(t reflect.Type, keys []settings.Key, tables []settings.Table) ([]Field, []error) {
	var out []Field
	var errs []error
	if t.Kind() != reflect.Struct {
		return nil, []error{fmt.Errorf("%s: раздел описывается структурой", t)}
	}
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			errs = append(errs, fmt.Errorf("%s.%s: нет имени поля в файле", t.Name(), sf.Name))
			continue
		}
		if opts != "" {
			errs = append(errs, fmt.Errorf("%s.%s: у поля раздела нет необязательности — пропавшее поле скрыло бы смену формы", t.Name(), sf.Name))
		}
		f := Field{JSON: name, Setting: sf.Tag.Get("setting"), Table: sf.Tag.Get("table")}
		switch {
		case (f.Setting == "") == (f.Table == ""):
			errs = append(errs, fmt.Errorf("%s.%s: нужна ровно одна метка — setting или table", t.Name(), sf.Name))
			continue
		case f.Setting != "":
			k, ok := declaredKey(keys, f.Setting)
			if !ok {
				errs = append(errs, fmt.Errorf("%s.%s: ключ %q не объявлен в реестре настроек", t.Name(), sf.Name, f.Setting))
				continue
			}
			if k.Prefix != (sf.Type.Kind() == reflect.Map) {
				errs = append(errs, fmt.Errorf("%s.%s: ключ с переменным хвостом — это словарь, обычный ключ — нет", t.Name(), sf.Name))
			}
			if ot, ok := settings.OwnerTable(tables, k.Owner); ok {
				errs = append(errs, fmt.Errorf("%s.%s: ключ %q принадлежит строкам таблицы %q — его место в поле строки, иначе в копии останется значение без своей строки", t.Name(), sf.Name, f.Setting, ot.Name))
			}
			f.Data, f.Risk, f.Title, f.Warn = k.Data, k.Risk, k.Title, k.Warn
		default:
			tb, ok := declaredTable(tables, f.Table)
			if !ok {
				errs = append(errs, fmt.Errorf("%s.%s: таблица %q не объявлена в реестре", t.Name(), sf.Name, f.Table))
				continue
			}
			if sf.Type.Kind() != reflect.Slice || sf.Type.Elem().Kind() != reflect.Struct {
				errs = append(errs, fmt.Errorf("%s.%s: таблица — это список строк-структур", t.Name(), sf.Name))
				continue
			}
			rows, rerrs := rowFields(sf.Type.Elem(), keys, tb)
			errs = append(errs, rerrs...)
			f.Data, f.Risk, f.Title, f.Warn, f.Rows = tb.Data, tb.Risk, tb.Title, tb.Warn, rows
		}
		out = append(out, f)
	}
	return out, errs
}

func rowFields(t reflect.Type, keys []settings.Key, tb settings.Table) ([]Field, []error) {
	var out []Field
	var errs []error
	ids := 0
	for i := range t.NumField() {
		sf := t.Field(i)
		name, opts, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if opts != "" {
			errs = append(errs, fmt.Errorf("%s.%s: у поля строки нет необязательности — пропавшее поле скрыло бы смену формы", t.Name(), sf.Name))
		}
		if r := sf.Tag.Get("ref"); r != "" && !refKinds[r] {
			errs = append(errs, fmt.Errorf("%s.%s: неизвестная ссылка на железо %q", t.Name(), sf.Name, r))
		}
		if o, ok := sf.Tag.Lookup("owner"); ok {
			if o != "id" || sf.Type.Kind() != reflect.String {
				errs = append(errs, fmt.Errorf("%s.%s: метка owner бывает только owner:\"id\" у строкового поля", t.Name(), sf.Name))
			}
			ids++
		}
		key := sf.Tag.Get("setting")
		if key == "" {
			continue
		}
		k, ok := declaredKey(keys, key)
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s.%s: ключ %q не объявлен в реестре настроек", t.Name(), sf.Name, key))
			continue
		case !k.Prefix || k.Owner == "" || k.Owner != tb.Owner || k.Section != tb.Section:
			errs = append(errs, fmt.Errorf("%s.%s: в строке таблицы %q лежат только ключи её владельца с переменным хвостом", t.Name(), sf.Name, tb.Name))
			continue
		case sf.Type.Kind() != reflect.String:
			errs = append(errs, fmt.Errorf("%s.%s: настройка строки — одно значение, строка", t.Name(), sf.Name))
		}
		out = append(out, Field{JSON: name, Setting: key, Data: k.Data, Risk: k.Risk, Title: k.Title, Warn: k.Warn})
	}
	if len(out) > 0 && ids != 1 {
		errs = append(errs, fmt.Errorf("%s: у строки с настройками ровно одно поле owner:\"id\" — хвост их ключей", t.Name()))
	}
	return out, errs
}

func declaredKey(keys []settings.Key, name string) (settings.Key, bool) {
	for _, k := range keys {
		if k.Name == name {
			return k, true
		}
	}
	return settings.Key{}, false
}

func declaredTable(tables []settings.Table, name string) (settings.Table, bool) {
	for _, t := range tables {
		if t.Name == name {
			return t, true
		}
	}
	return settings.Table{}, false
}

const coveredByKeys = "settings"

func Check(entries []Entry, keys []settings.Key, tables []settings.Table) []error {
	var errs []error
	seen := map[settings.Section]bool{}
	settingOwner := map[string]string{}
	tableOwner := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if name == "" || seen[name] {
			errs = append(errs, fmt.Errorf("раздел %q без имени или объявлен дважды", name))
		}
		seen[name] = true
		if e.Spec().Version < 1 {
			errs = append(errs, fmt.Errorf("раздел %q: версия меньше 1", name))
		}
		if !e.HasValidate() {
			errs = append(errs, fmt.Errorf("раздел %q: нет проверки — импорт принял бы данные, которые форма отвергает", name))
		}
		if !e.HasApply() {
			errs = append(errs, fmt.Errorf("раздел %q: нет применения — импорт записал бы раздел не тем путём, что форма", name))
		}
		fields, ferrs := Fields(e.Shape(), keys, tables)
		errs = append(errs, ferrs...)
		for _, f := range fields {
			for _, r := range f.Rows {
				if prev, dup := settingOwner[r.Setting]; dup {
					errs = append(errs, fmt.Errorf("%q описан дважды: в разделах %q и %q", r.Setting, prev, name))
				}
				settingOwner[r.Setting] = string(name)
			}
			owner, what, sec := settingOwner, f.Setting, sectionOf(keys, tables, f)
			if f.Table != "" {
				owner, what = tableOwner, f.Table
			}
			if sec != name {
				errs = append(errs, fmt.Errorf("раздел %q: %q по реестру относится к разделу %q", name, what, sec))
			}
			if !f.Data.InCopy() {
				errs = append(errs, fmt.Errorf("раздел %q: %q по реестру не переносится в копию", name, what))
			}
			if prev, dup := owner[what]; dup {
				errs = append(errs, fmt.Errorf("%q описан дважды: в разделах %q и %q", what, prev, name))
			}
			owner[what] = string(name)
		}
	}
	for _, k := range keys {
		if k.Data.InCopy() && settingOwner[k.Name] == "" {
			errs = append(errs, fmt.Errorf("настройка %q переносится в копию, но нет поля раздела с меткой setting:%q", k.Name, k.Name))
		}
	}
	for _, t := range tables {
		if t.Name != coveredByKeys && t.Data.InCopy() && tableOwner[t.Name] == "" {
			errs = append(errs, fmt.Errorf("таблица %q переносится в копию, но нет поля раздела с меткой table:%q", t.Name, t.Name))
		}
	}
	if _, err := Order(entries); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func sectionOf(keys []settings.Key, tables []settings.Table, f Field) settings.Section {
	if f.Table != "" {
		t, _ := declaredTable(tables, f.Table)
		return t.Section
	}
	k, _ := declaredKey(keys, f.Setting)
	return k.Section
}

func Order(entries []Entry) ([]Entry, error) {
	byName := map[settings.Section]Entry{}
	for _, e := range entries {
		byName[e.Name()] = e
	}
	for _, e := range entries {
		for _, dep := range e.After() {
			if _, ok := byName[dep]; !ok {
				return nil, fmt.Errorf("раздел %q зависит от неизвестного раздела %q", e.Name(), dep)
			}
		}
	}
	done := map[settings.Section]bool{}
	var out []Entry
	for len(out) < len(entries) {
		progress := false
		for _, e := range entries {
			if done[e.Name()] || !allDone(e.After(), done) {
				continue
			}
			done[e.Name()] = true
			out = append(out, e)
			progress = true
		}
		if !progress {
			var stuck []string
			for _, e := range entries {
				if !done[e.Name()] {
					stuck = append(stuck, string(e.Name()))
				}
			}
			return nil, fmt.Errorf("зависимости разделов замкнуты в цикл: %s", strings.Join(stuck, ", "))
		}
	}
	return out, nil
}

func allDone(deps []settings.Section, done map[settings.Section]bool) bool {
	for _, d := range deps {
		if !done[d] {
			return false
		}
	}
	return true
}
