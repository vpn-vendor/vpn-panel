package models

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var directionInColumn = regexp.MustCompile(`OrderBy\("[^"]*\s(?i:asc|desc)\s*"\s*\)`)

func TestNoDirectionInOrderByColumn(t *testing.T) {
	for _, bad := range []string{`OrderBy("id desc")`, `OrderBy("created_at DESC")`, `OrderBy("x asc")`} {
		if !directionInColumn.MatchString(bad) {
			t.Fatalf("страж не узнаёт %s", bad)
		}
	}
	for _, good := range []string{`OrderByDesc("id")`, `OrderBy("id")`, `OrderBy("id", "desc")`} {
		if directionInColumn.MatchString(good) {
			t.Fatalf("страж ошибочно ловит %s", good)
		}
	}
	scanned := 0
	for _, root := range []string{"../../app", "../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			data, err := os.ReadFile(p) //nolint:gosec
			if err != nil {
				return err
			}
			scanned++
			for _, m := range directionInColumn.FindAll(data, -1) {
				t.Errorf("%s: %s — направление сортировки в имени столбца, используйте OrderByDesc", p, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned == 0 {
		t.Fatal("страж не нашёл ни одного файла — поиск сломан")
	}
}
