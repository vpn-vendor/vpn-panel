package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
)

func openPages(t *testing.T) *template.Template {
	t.Helper()
	root := filepath.Join("..", "..", "..", "resources", "views")
	files := []string{filepath.Join(root, "partials.tmpl")}
	for _, name := range []string{"login.tmpl", "setup.tmpl", "whoami.tmpl", "lantest.tmpl"} {
		files = append(files, filepath.Join(root, name))
	}
	atoms, err := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	if err != nil || len(atoms) == 0 {
		t.Fatalf("атомы не найдены: %v", err)
	}
	files = append(files, atoms...)
	tpl, err := template.ParseFiles(files...)
	if err != nil {
		t.Fatalf("шаблоны открытых страниц не разбираются: %v", err)
	}
	return tpl
}

func renderOpen(t *testing.T, name string, data map[string]any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := openPages(t).ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("%s не отрисовался: %v", name, err)
	}
	return buf.String()
}

func TestOpenPagesCarryNoMarksForVisitors(t *testing.T) {
	cases := map[string]map[string]any{
		"login.tmpl":   {"title": "Вход", "onServer": false},
		"setup.tmpl":   {"title": "Установка", "needCode": true},
		"whoami.tmpl":  {"title": "Это я"},
		"lantest.tmpl": {"title": "Скорость до сервера"},
	}
	for name, data := range cases {
		out := strings.ToLower(renderOpen(t, name, data))
		for _, mark := range []string{"vpn-panel", "vpn-vendor", "vpn panel", "brand-name", "pro-pill"} {
			if strings.Contains(out, mark) {
				t.Fatalf("%s отдаёт постороннему опознавательный знак %q", name, mark)
			}
		}
	}
}

func TestLoginShowsCommandOnServerItself(t *testing.T) {
	out := renderOpen(t, "login.tmpl", map[string]any{"title": "Вход", "onServer": true})
	if !strings.Contains(out, "vpn-panel-code") {
		t.Fatalf("на самом сервере имя консольной команды не показано")
	}
}
