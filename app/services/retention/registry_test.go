package retention

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	migrationsDir = "../../../database/migrations"
	modelsDir     = "../../models"
)

var (
	createRe    = regexp.MustCompile(`Schema\(\)\.Create\("([a-z0-9_]+)"`)
	tableNameRe = regexp.MustCompile(`TableName\(\) string \{ return "([a-z0-9_]+)" \}`)
)

func scan(t *testing.T, dir string, re *regexp.Regexp) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("нет файлов в %s: %v", dir, err)
	}
	var names []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			names = append(names, m[1])
		}
	}
	return names
}

func tablesInTree(t *testing.T) []string {
	set := map[string]bool{}
	for _, n := range scan(t, migrationsDir, createRe) {
		set[n] = true
	}
	for _, n := range scan(t, modelsDir, tableNameRe) {
		set[n] = true
	}
	for _, n := range FrameworkTables {
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func check(declared []Ceiling, tables []string) []string {
	var errs []string
	byName := map[string]Ceiling{}
	for _, c := range declared {
		if _, dup := byName[c.Name]; dup {
			errs = append(errs, "объявлено дважды: "+c.Name)
		}
		byName[c.Name] = c
		if c.Name == "" || c.Limit == "" || c.Age == "" || c.OnCeiling == "" {
			errs = append(errs, "пустое поле объявления: "+c.Name)
		}
		switch c.Class {
		case Critical, Ordinary, Cache, Unused:
		default:
			errs = append(errs, "неизвестный класс у "+c.Name)
		}
		switch c.Growth {
		case ByNetwork, ByAdmin, ByCode, ByTime:
		default:
			errs = append(errs, "неизвестный источник роста у "+c.Name)
		}
		switch {
		case !c.Enforced && c.Debt == "":
			errs = append(errs, "потолок не соблюдается и долг не указан: "+c.Name)
		case c.Enforced && c.Debt != "":
			errs = append(errs, "потолок соблюдается, а долг всё ещё указан: "+c.Name)
		}
	}
	inTree := map[string]bool{}
	for _, tbl := range tables {
		inTree[tbl] = true
		c, ok := byName[tbl]
		switch {
		case !ok:
			errs = append(errs, "таблица без объявленного потолка (закон): "+tbl)
		case c.Kind != Table:
			errs = append(errs, "таблица объявлена не таблицей: "+tbl)
		}
	}
	for _, c := range declared {
		if c.Kind == Table && !inTree[c.Name] {
			errs = append(errs, "объявлена таблица, которой нет ни в миграциях, ни в моделях: "+c.Name)
		}
	}
	return errs
}

func checkDebts(declared []Ceiling, registry string) []string {
	var errs []string
	for _, c := range declared {
		if !c.Enforced && c.Debt != "" && !strings.Contains(registry, "- id: "+c.Debt+"\n") {
			errs = append(errs, "долг "+c.Debt+" у "+c.Name+" не найден в реестре проверок")
		}
	}
	return errs
}

func TestEveryGrowingEntityDeclared(t *testing.T) {
	tables := tablesInTree(t)
	if len(tables) < 10 {
		t.Fatalf("разбор дерева нашёл подозрительно мало таблиц (%d) — сломан сам тест: %v", len(tables), tables)
	}
	for _, e := range check(Declared, tables) {
		t.Error(e)
	}
}

func TestCheckRedOnViolations(t *testing.T) {
	ok := Ceiling{Name: "a", Kind: Table, Class: Ordinary, Growth: ByTime, Limit: "l", Age: "a", OnCeiling: "o", Enforced: true}
	cases := []struct {
		name     string
		declared []Ceiling
		tables   []string
	}{
		{"незаявленная таблица", []Ceiling{ok}, []string{"a", "b"}},
		{"заявленная несуществующая", []Ceiling{ok, {Name: "ghost", Kind: Table, Class: Ordinary, Growth: ByTime, Limit: "l", Age: "a", OnCeiling: "o", Enforced: true}}, []string{"a"}},
		{"не соблюдается без долга", []Ceiling{{Name: "a", Kind: Table, Class: Ordinary, Growth: ByNetwork, Limit: "l", Age: "a", OnCeiling: "o"}}, []string{"a"}},
		{"соблюдается, но долг остался", []Ceiling{{Name: "a", Kind: Table, Class: Ordinary, Growth: ByTime, Limit: "l", Age: "a", OnCeiling: "o", Enforced: true, Debt: "D-1"}}, []string{"a"}},
		{"пустой потолок", []Ceiling{{Name: "a", Kind: Table, Class: Ordinary, Growth: ByTime, Age: "a", OnCeiling: "o", Enforced: true}}, []string{"a"}},
		{"неизвестный класс", []Ceiling{{Name: "a", Kind: Table, Class: "x", Growth: ByTime, Limit: "l", Age: "a", OnCeiling: "o", Enforced: true}}, []string{"a"}},
		{"дубликат", []Ceiling{ok, ok}, []string{"a"}},
	}
	for _, c := range cases {
		if errs := check(c.declared, c.tables); len(errs) == 0 {
			t.Errorf("%s: страж промолчал", c.name)
		}
	}
	if errs := check([]Ceiling{ok}, []string{"a"}); len(errs) != 0 {
		t.Fatalf("чистое объявление обязано проходить: %v", errs)
	}
}

func TestCheckDebtsRedOnMissing(t *testing.T) {
	registry := "- id: D-1\n"
	debt := func(id string) []Ceiling {
		return []Ceiling{{Name: "a", Kind: Table, Class: Ordinary, Growth: ByNetwork, Limit: "l", Age: "a", OnCeiling: "o", Debt: id}}
	}
	if errs := checkDebts(debt("D-2"), registry); len(errs) == 0 {
		t.Error("долг не в реестре: страж промолчал")
	}
	if errs := checkDebts(debt("D-1"), registry); len(errs) != 0 {
		t.Fatalf("записанный долг обязан проходить: %v", errs)
	}
}
