package vpnproto_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

type allowance struct {
	why         string
	importsOnly bool
}

var allowed = map[string]allowance{
	"internal/wggen/":                    {"модуль протокола", false},
	"internal/ovpngen/":                  {"модуль протокола", false},
	"internal/vpnproto/":                 {"корень сборки: список модулей", true},
	"cmd/vpn-agent/vpn.go":               {"таблица состава агента: конструкторы драйверов и чтение метки", true},
	"cmd/vpn-agent/vpn_wg.go":            {"драйвер агента", false},
	"cmd/vpn-agent/vpn_ovpn.go":          {"драйвер агента", false},
	"cmd/vpn-agent/backup_secrets_v1.go": {"застывший формат копии секретов версии 1 — только чтение старых копий", false},
	"database/migrations/":               {"застывшая история: смысл миграции не меняется вместе с кодом", false},
}

func isAllowed(rel string) (string, allowance, bool) {
	for p, a := range allowed {
		if rel == p || strings.HasPrefix(rel, p) {
			return p, a, true
		}
	}
	return "", allowance{}, false
}

func markers() []string {
	var out []string
	for _, d := range vpnproto.All() {
		out = append(out, strings.ToLower(string(d.ID)), strings.ToLower(d.Label), strings.ToLower(d.Iface))
	}
	return out
}

func modulePackages() map[string]bool {
	out := map[string]bool{}
	for _, d := range vpnproto.All() {
		name := runtime.FuncForPC(reflect.ValueOf(d.Marks).Pointer()).Name()
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[:i] + "/" + strings.SplitN(name[i+1:], ".", 2)[0]
		}
		out[name] = true
	}
	return out
}

type hit struct {
	rel, what string
	imp       bool
}

func scanGo(rel, src string, marks []string, mods map[string]bool) []hit {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []hit{{rel, "не разобран: " + err.Error(), false}}
	}
	var out []hit
	imports := map[*ast.BasicLit]bool{}
	for _, imp := range f.Imports {
		imports[imp.Path] = true
		if p, _ := strconv.Unquote(imp.Path.Value); mods[p] {
			out = append(out, hit{rel, "импорт модуля протокола " + p, true})
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || imports[lit] {
			return true
		}
		low := strings.ToLower(lit.Value)
		for _, m := range marks {
			if strings.Contains(low, m) {
				out = append(out, hit{rel, "литерал " + lit.Value, false})
				break
			}
		}
		return true
	})
	return out
}

func moduleRoot(t *testing.T) string {
	dir, _ := os.Getwd()
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("корень модуля не найден")
	return ""
}

var skipDirs = regexp.MustCompile(`(^|/)(\.git|dist|node_modules|vendor|testdata)(/|$)`)

func TestProtocolKnowledgeStaysInModules(t *testing.T) {
	root := moduleRoot(t)
	marks, mods := markers(), modulePackages()
	if len(mods) != len(vpnproto.All()) {
		t.Fatalf("пакеты модулей не определены по описаниям: %v", mods)
	}
	used := map[string]bool{}
	var bad []string
	_ = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, path)
		if err != nil || skipDirs.MatchString(rel) {
			if e != nil && e.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if e.IsDir() || !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, _ := os.ReadFile(path) //nolint:gosec
		hits := scanGo(rel, string(src), marks, mods)
		if len(hits) == 0 {
			return nil
		}
		p, a, ok := isAllowed(rel)
		for _, h := range hits {
			if ok && (!a.importsOnly || h.imp) {
				used[p] = true
				continue
			}
			bad = append(bad, h.rel+": "+h.what)
		}
		return nil
	})
	for _, dir := range []string{"resources/views", "public/js"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			src, _ := os.ReadFile(path) //nolint:gosec
			low := strings.ToLower(string(src))
			rel, _ := filepath.Rel(root, path)
			for _, m := range marks {
				if strings.Contains(low, m) {
					bad = append(bad, rel+": «"+m+"» — подпись и расширения берутся из описаний протоколов")
				}
			}
			return nil
		})
	}
	for p, a := range allowed {
		if !used[p] {
			bad = append(bad, "исключение «"+p+"» ("+a.why+") больше не нужно — уберите его из списка")
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

func TestPackagingKnowsEveryProtocol(t *testing.T) {
	root := moduleRoot(t)
	control, _ := os.ReadFile(filepath.Join(root, "debian", "control")) //nolint:gosec
	postrm, _ := os.ReadFile(filepath.Join(root, "debian", "postrm"))   //nolint:gosec
	deps := regexp.MustCompile(`(?ms)^Depends:(.*?)^\S`).FindSubmatch(control)
	if deps == nil {
		t.Fatal("в debian/control нет Depends")
	}
	for _, d := range vpnproto.All() {
		for _, p := range d.Packages {
			if !regexp.MustCompile(`(^|[\s,])` + regexp.QuoteMeta(p) + `([\s,]|$)`).Match(deps[1]) {
				t.Errorf("%s: пакета %s нет в зависимостях", d.ID, p)
			}
		}
		if !strings.Contains(string(postrm), "ip link del "+d.Iface) {
			t.Errorf("%s: при удалении пакета интерфейс %s не убирается", d.ID, d.Iface)
		}
	}
}

func TestGuardFindsPlantedKnowledge(t *testing.T) {
	marks, mods := markers(), modulePackages()
	var mod string
	for m := range mods {
		mod = m
	}
	planted := "package x\nimport m \"" + mod + "\"\nvar _ = m.ID\nvar s = \"Файл " + vpnproto.All()[0].Label + " не подошёл\"\n"
	if got := scanGo("app/x.go", planted, marks, mods); len(got) != 2 {
		t.Fatalf("подложенные литерал и импорт: найдено %v", got)
	}
	clean := "package x\nimport \"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto\"\nvar _ = vpnproto.All\n"
	if got := scanGo("app/y.go", clean, marks, mods); len(got) != 0 {
		t.Fatalf("законная ссылка на корень принята за нарушение: %v", got)
	}
}
