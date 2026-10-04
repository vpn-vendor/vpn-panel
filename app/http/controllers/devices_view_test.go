package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevicesDoneIsNotACode(t *testing.T) {
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "devices.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"title": "Устройства", "active": "devices", "done": "Выход выполнен на 3 устройствах.",
		"aliveCount": 1, "deadCount": 5, "trustDays": 30, "canSignOut": true}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "devices.tmpl", data); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "Выход выполнен на 3 устройствах.") || strings.Contains(html, "Код подключения") {
		t.Fatal("итог действия показан не строкой успеха, а как код подключения")
	}
	if !strings.Contains(html, "Ещё 5 вышли") || !strings.Contains(html, "30 дней") {
		t.Fatal("мёртвые доверия обязаны быть одной строкой-числом со сроком хранения")
	}
}
