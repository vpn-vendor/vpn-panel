package durable_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var allowed = map[string]string{
	"cmd/vpn-agent/main.go":                     "сокет службы: живёт в памяти, пересоздаётся при каждом запуске",
	"cmd/vpn-agent/netplan.go":                  "проверка плана в одноразовом каталоге, который удаляется всегда",
	"cmd/vpn-agent/dhcp.go":                     "владелец и права каталога конфигурации, не содержимое файла",
	"cmd/vpn-agent/disk_setup.go":               "консоль загрузки — устройство, не файл",
	"cmd/vpn-agent/disk_console.go":             "консоль загрузки — устройство, не файл",
	"cmd/vpn-agent/logs.go":                     "обрезка чужих журналов на месте: файл открыт их службой",
	"app/services/restore/live.go":              "файл блокировки: важен замок, а не содержимое",
	"app/http/controllers/vpn_controller.go":    "временный файл загрузки формы, создан не нами",
	"app/http/controllers/backup_controller.go": "временный файл загрузки формы, создан не нами",
}

var forbidden = map[string]bool{
	"WriteFile": true, "Create": true, "CreateTemp": true, "Rename": true, "Remove": true,
	"RemoveAll": true, "OpenFile": true, "Truncate": true, "Chmod": true, "Chown": true,
	"Lchown": true, "Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "Link": true, "Symlink": true,
}

func TestFilesAreWrittenOnlyThroughThisPackage(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	for _, top := range []string{"cmd", "app", "internal", "bootstrap", "config", "routes", "database", "main.go"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
			if strings.HasPrefix(rel, "internal/durable/") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Errorf("%s: %v", rel, perr)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if ok && (pkg.Name == "os" || pkg.Name == "ioutil") && forbidden[sel.Sel.Name] {
					found[rel] = append(found[rel], pkg.Name+"."+sel.Sel.Name+" в строке "+
						strings.TrimPrefix(fset.Position(call.Pos()).String(), path+":"))
				}
				return true
			})
			return nil
		})
	}
	var files []string
	for rel := range found {
		files = append(files, rel)
	}
	sort.Strings(files)
	for _, rel := range files {
		if _, ok := allowed[rel]; !ok {
			t.Errorf("%s пишет файлы мимо надёжной записи: %s", rel, strings.Join(found[rel], "; "))
		}
	}
	for rel := range allowed {
		if len(found[rel]) == 0 {
			t.Errorf("исключение для %s устарело: прямых операций с файлами там больше нет", rel)
		}
	}
}
