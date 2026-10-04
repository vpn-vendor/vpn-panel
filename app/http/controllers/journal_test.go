package controllers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
)

func TestEventCatalogCoversEveryAuditCode(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	re := regexp.MustCompile(`Audit\("([a-z_]+)"|Event:\s*"([a-z_]+)"`)
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "app"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if m[1] != "" {
				found[m[1]] = true
			} else if m[2] != "" {
				found[m[2]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("в исходниках не найдено ни одного Audit(\"…\") — тест смотрит не туда")
	}
	for code := range found {
		if _, ok := securitylog.Lookup(code); !ok {
			t.Errorf("событие %q пишется в журнал, но его нет в каталоге кодов", code)
		}
	}

	for _, code := range pathmon.EventCodes() {
		if e, ok := securitylog.Lookup(code); !ok || e.Class != securitylog.System {
			t.Errorf("код пути %q обязан быть в каталоге системным: %+v", code, e)
		}
	}
	if eventTitle("nonexistent_code") != securitylog.UnknownTitle {
		t.Fatal("неизвестный код обязан показываться человеческим словом, не кодом")
	}
}
