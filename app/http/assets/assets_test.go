package assets

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestFingerprintFollowsContent(t *testing.T) {
	a := fstest.MapFS{"css/app.css": {Data: []byte("a{}")}, "js/app.js": {Data: []byte("1")}}
	same := fstest.MapFS{"js/app.js": {Data: []byte("1")}, "css/app.css": {Data: []byte("a{}")}}
	if Of(a) == "" || Of(a) != Of(same) {
		t.Fatalf("одинаковый состав дал разные отпечатки: %q и %q", Of(a), Of(same))
	}
	changed := fstest.MapFS{"css/app.css": {Data: []byte("a{color:red}")}, "js/app.js": {Data: []byte("1")}}
	renamed := fstest.MapFS{"css/app2.css": {Data: []byte("a{}")}, "js/app.js": {Data: []byte("1")}}
	for name, fsys := range map[string]fstest.MapFS{"изменённое содержимое": changed, "переименованный файл": renamed} {
		if Of(fsys) == Of(a) {
			t.Errorf("%s: отпечаток не изменился", name)
		}
	}
	if len(Of(a)) != fingerprintLen {
		t.Errorf("длина отпечатка %d", len(Of(a)))
	}
	if Of(fstest.MapFS{}) != "" {
		t.Error("у пустого каталога есть отпечаток")
	}
}

func TestPanelStaticHasFingerprint(t *testing.T) {
	root := filepath.Join("..", "..", "..", Dir)
	if fp := Of(os.DirFS(root)); fp == "" {
		t.Fatal("статика панели не найдена или пуста")
	}
}
