package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestErrorCodesAreNamedAndUnique(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	byNumber := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.ValueSpec:
				for i, id := range v.Names {
					if !strings.HasPrefix(id.Name, "code") || i >= len(v.Values) {
						continue
					}
					lit, ok := v.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						continue
					}
					if other, dup := byNumber[lit.Value]; dup {
						t.Errorf("код %s у двух отказов: %s и %s", lit.Value, other, id.Name)
					}
					byNumber[lit.Value] = id.Name
				}
			case *ast.KeyValueExpr:
				key, ok := v.Key.(*ast.Ident)
				if !ok || key.Name != "Code" {
					return true
				}
				if lit, ok := v.Value.(*ast.BasicLit); ok && lit.Kind == token.INT {
					t.Errorf("%s: код %s записан числом в отказе — дайте ему имя", fset.Position(v.Pos()), lit.Value)
				}
			case *ast.CallExpr:

				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Busy" && len(v.Args) > 0 {
					if lit, ok := v.Args[0].(*ast.BasicLit); ok && lit.Kind == token.INT {
						t.Errorf("%s: код %s записан числом в отказе — дайте ему имя", fset.Position(v.Pos()), lit.Value)
					}
				}
			}
			return true
		})
	}
	for num := range byNumber {
		if n, _ := strconv.Atoi(num); n >= -32768 && n <= -32000 {
			t.Errorf("код %s в диапазоне, занятом протоколом", num)
		}
	}
}
