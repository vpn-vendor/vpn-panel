package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

func ShapeErrors(entries []Entry, dir string) []error {
	errs := backupfile.GoldenErrors(Specs(entries), dir)
	for _, e := range entries {
		v := e.Spec().Version
		p := filepath.Join(dir, string(e.Name()), fmt.Sprintf("v%d.json", v))
		golden, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			continue
		}
		val, err := e.Decode(golden)
		if err != nil {
			errs = append(errs, fmt.Errorf("раздел %q: эталон v%d не подходит к структуре раздела (%v) — форма изменилась: поднимите версию, добавьте шаг миграции и эталон", e.Name(), v, err))
			continue
		}
		back, _ := json.Marshal(val)
		if !sameJSON(back, golden) {
			errs = append(errs, fmt.Errorf("раздел %q: структура выводит не то, что эталон v%d — форма изменилась: поднимите версию, добавьте шаг миграции и эталон", e.Name(), v))
		}
	}
	return errs
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
