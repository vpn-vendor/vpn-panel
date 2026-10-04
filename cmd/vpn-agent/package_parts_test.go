package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPackagePartsLiveInOwnFiles(t *testing.T) {
	rules := readRepo(t, "debian/rules")
	for _, want := range []string{"include $(sort $(wildcard debian/rules.d/*.mk))", "override_dh_auto_install: $(INSTALL_PARTS)"} {
		if !strings.Contains(rules, want) {
			t.Errorf("общий файл сборки потерял строку %q — части пакета не подключатся", want)
		}
	}
	payload := regexp.MustCompile(`(?m)^\t\s*(install|cp|mkdir|rsvg-convert)\b`)
	if m := payload.FindString(rules); m != "" {
		t.Errorf("в общем файле сборки строка установки %q: ей место в файле своего предмета", strings.TrimSpace(m))
	}

	dir := filepath.Join("..", "..", "debian", "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := regexp.MustCompile(`(?m)^(install-[a-z-]+):$`)
	seen := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".mk") {
			t.Errorf("%s: в каталоге частей только файлы частей", e.Name())
			continue
		}
		text := readRepo(t, "debian/rules.d/"+e.Name())
		found := target.FindAllStringSubmatch(text, -1)
		if len(found) != 1 {
			t.Errorf("%s: в файле части ровно одна цель установки, найдено %d", e.Name(), len(found))
			continue
		}
		name := found[0][1]
		if prev, dup := seen[name]; dup {
			t.Errorf("%s: цель %s уже объявлена в %s", e.Name(), name, prev)
		}
		seen[name] = e.Name()
		if !strings.Contains(text, "INSTALL_PARTS += "+name+"\n") || !strings.Contains(text, ".PHONY: "+name+"\n") {
			t.Errorf("%s: цель %s не подключена к сборке", e.Name(), name)
		}
		if !strings.HasPrefix(text, "# ") {
			t.Errorf("%s: первой строкой — что это за предмет", e.Name())
		}
	}

	if len(entries) == 0 || entries[0].Name() != "00-base.mk" {
		t.Error("первой частью обязана идти основа пакета")
	}
}
