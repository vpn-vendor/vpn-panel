package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

var (
	registryKeys   = settings.Keys
	registryTables = settings.Tables
)

func Build(entries []Entry, kind backupfile.Kind, panelVersion string, now time.Time) (*backupfile.Document, error) {
	doc := &backupfile.Document{
		Format: backupfile.FormatName, FormatVersion: backupfile.FormatVersion, Kind: kind,
		PanelVersion: panelVersion, CreatedAt: now.UTC(), Sections: map[string]backupfile.Section{},
	}
	for _, e := range entries {
		data, err := e.Export()
		if err != nil {
			return nil, fmt.Errorf("раздел %q: %w", e.Name(), err)
		}
		if kind == backupfile.KindTemplate {
			if data, err = templateOnly(e, data); err != nil {
				return nil, fmt.Errorf("раздел %q: %w", e.Name(), err)
			}
			if data == nil {
				continue
			}
		}
		doc.Sections[string(e.Name())] = backupfile.Section{Version: e.Spec().Version, Data: data}
	}
	return doc, nil
}

func templateOnly(e Entry, data json.RawMessage) (json.RawMessage, error) {
	fields, errs := Fields(e.Shape(), registryKeys, registryTables)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	for _, f := range fields {
		if !settings.InTemplate(f.Data, f.Risk) {
			delete(obj, f.JSON)
			continue
		}
		if err := rowsTemplateOnly(obj, f); err != nil {
			return nil, err
		}
	}
	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj)
}

func rowsTemplateOnly(obj map[string]json.RawMessage, f Field) error {
	var drop []string
	for _, r := range f.Rows {
		if !settings.InTemplate(r.Data, r.Risk) {
			drop = append(drop, r.JSON)
		}
	}
	if len(drop) == 0 || obj[f.JSON] == nil {
		return nil
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(obj[f.JSON], &rows); err != nil {
		return err
	}
	for _, r := range rows {
		for _, d := range drop {
			delete(r, d)
		}
	}
	b, err := json.Marshal(rows)
	obj[f.JSON] = b
	return err
}

func Dangerous(e Entry) ([]Field, error) {
	fields, errs := Fields(e.Shape(), registryKeys, registryTables)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var out []Field
	for _, f := range fields {
		if f.Risk == settings.Dangerous {
			out = append(out, f)
		}
		for _, r := range f.Rows {
			if r.Risk == settings.Dangerous {
				r.JSON = f.JSON + "[]." + r.JSON
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", backupfile.ErrMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: лишние данные после раздела", backupfile.ErrMalformed)
	}
	return nil
}
