package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConsoleDevices(t *testing.T) {
	cases := map[string][]string{
		"tty0 ttyS0\n": {"/dev/tty0", "/dev/ttyS0"},
		"tty0\n":       {"/dev/tty0"},
		"":             {"/dev/console"},
		"../etc tty0":  {"/dev/tty0"},
	}
	for in, want := range cases {
		if got := consoleDevices(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, ждали %v", in, got, want)
		}
	}
}

func TestFdsDraw(t *testing.T) {
	dir := t.TempDir()
	if fdsDraw(dir) {
		t.Fatal("без открытых файлов — текст")
	}
	link := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	link("/dev/tty7", filepath.Join(dir, "0"))
	link("socket:[123]", filepath.Join(dir, "1"))
	if fdsDraw(dir) {
		t.Fatal("только консоль и сокет — текст")
	}
	link("/dev/dri/card0", filepath.Join(dir, "2"))
	if !fdsDraw(dir) {
		t.Fatal("открыт /dev/dri/card0 — рисует")
	}
	fb := t.TempDir()
	link("/dev/fb0", filepath.Join(fb, "3"))
	if !fdsDraw(fb) {
		t.Fatal("открыт /dev/fb0 — рисует")
	}
	if fdsDraw(filepath.Join(dir, "нет")) || plymouthDraws(filepath.Join(dir, "нет-pid")) {
		t.Fatal("нет каталога или файла pid — текст")
	}
}
