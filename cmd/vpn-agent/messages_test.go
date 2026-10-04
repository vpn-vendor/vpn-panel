package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func isCyrillic(r rune) bool { return unicode.Is(unicode.Cyrillic, r) }

func TestErrorMessagesAreHuman(t *testing.T) {
	re := regexp.MustCompile(`(?:internalErr|detailErr)\("([^"]*)"|Message:\s*"([^"]*)"`)
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			text := m[1] + m[2]
			if text == "" {
				continue
			}
			checked++
			if !strings.ContainsFunc(text, isCyrillic) {
				t.Errorf("%s: текст ошибки без кириллицы: %q", f, text)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("проверено слишком мало текстов (%d) — регулярное выражение не находит их", checked)
	}
	if !strings.ContainsFunc(errReadInterfaces, isCyrillic) {
		t.Fatal("общие тексты обязаны быть русскими")
	}
}
