package backupfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func GoldenErrors(specs Specs, dir string) []error {
	var errs []error
	for name, sp := range specs {
		current, err := readGolden(dir, name, sp.Version)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for v := 1; v <= sp.Version; v++ {
			data, err := readGolden(dir, name, v)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			doc := &Document{Sections: map[string]Section{name: {Version: v, Data: data}}}
			if err := (Specs{name: sp}).Migrate(doc); err != nil {
				errs = append(errs, fmt.Errorf("раздел %q v%d: %w", name, v, err))
				continue
			}
			same, err := jsonEqual(doc.Sections[name].Data, current)
			if err != nil {
				errs = append(errs, fmt.Errorf("раздел %q v%d: %w", name, v, err))
				continue
			}
			if !same {
				errs = append(errs, fmt.Errorf("раздел %q: миграция от v%d не даёт эталон v%d", name, v, sp.Version))
			}
		}
	}
	return errs
}

func readGolden(dir, name string, v int) (json.RawMessage, error) {
	p := filepath.Join(dir, name, fmt.Sprintf("v%d.json", v))
	data, err := os.ReadFile(p) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("раздел %q: нет эталона версии %d (%s)", name, v, p)
	}
	return data, nil
}

func jsonEqual(a, b []byte) (bool, error) {
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false, err
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya), nil
}
