package agentrpc_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPanelDoesNotBranchOnErrorNumbers(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	isCode := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Code"
	}
	isNumber := func(e ast.Expr) bool {
		lit, ok := e.(*ast.BasicLit)
		return ok && lit.Kind == token.INT && lit.Value != "0"
	}
	for _, top := range []string{"app", "bootstrap", "routes"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Errorf("%s: %v", path, perr)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.BinaryExpr:
					if (isCode(v.X) && isNumber(v.Y)) || (isCode(v.Y) && isNumber(v.X)) {
						t.Errorf("%s: код отказа сравнивается с числом — решайте по свойству отказа", fset.Position(v.Pos()))
					}
				case *ast.SwitchStmt:
					if v.Tag == nil || !isCode(v.Tag) {
						return true
					}
					for _, st := range v.Body.List {
						for _, e := range st.(*ast.CaseClause).List {
							if isNumber(e) {
								t.Errorf("%s: код отказа сравнивается с числом — решайте по свойству отказа", fset.Position(e.Pos()))
							}
						}
					}
				case *ast.ValueSpec:

					for i, id := range v.Names {
						if strings.HasPrefix(strings.ToLower(id.Name), "agent") && i < len(v.Values) && isNumber(v.Values[i]) {
							t.Errorf("%s: номер отказа службы %s записан в панели", fset.Position(id.Pos()), id.Name)
						}
					}
				}
				return true
			})
			return nil
		})
	}
}
