package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func homeRun(t *testing.T, root string, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := legacyHome(root, args, &out, &errOut)
	if code != 0 {
		return errOut.String(), code
	}
	return out.String(), 0
}

func TestLegacyHomeScan(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "root/vpn.sh", "#!/bin/bash\n")
	writeFixture(t, root, tkHome("u")[1:], "#!/bin/bash\n")
	writeFixture(t, root, "home/w/x/vpn.sh", "#!/bin/bash\n")
	writeFixture(t, root, "home/v/other.sh", "#!/bin/bash\n")
	if err := os.Symlink(filepath.Join(root, tkHome("u")), filepath.Join(root, tkHome("v"))); err != nil {
		t.Fatal(err)
	}
	out, code := homeRun(t, root, "scan")
	if code != 0 {
		t.Fatal(out)
	}
	paths, err := parseHomeScan([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(paths, []string{"/root/vpn.sh", tkHome("u")}) {
		t.Fatalf("найдено: %v", paths)
	}
	if _, err := parseHomeScan([]byte(`["/etc/passwd"]`)); err == nil {
		t.Fatal("чужой путь в ответе принят")
	}
	if out, code := homeRun(t, t.TempDir(), "scan"); code != 0 || out != "[]\n" {
		t.Fatalf("пустая машина: %q %d", out, code)
	}
}

func TestLegacyHomeStub(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, tkHome("office")[1:], tkScript)
	if err := os.Chmod(filepath.Join(root, tkHome("office")), 0o750); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	bk := takeoverBackupRoot + "/takeover-20261020T101500Z"
	out, code := homeRun(t, root, "stub", tkHome("office"), bk)
	if code != 0 {
		t.Fatal(out)
	}
	var entry takeoverCopy
	if err := json.Unmarshal([]byte(out), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Path != tkHome("office") || entry.Mode != 0o750 || entry.UID != os.Getuid() || entry.SHA256 != sha256Hex([]byte(tkScript)) {
		t.Fatalf("запись описи: %+v", entry)
	}
	if got := readText(t, root, bk+tkHome("office")); got != tkScript {
		t.Fatalf("копия: %q", got)
	}
	if got := readText(t, root, tkHome("office")); got != legacyStubScript {
		t.Fatalf("заглушка: %q", got)
	}
	fi, _ := os.Stat(filepath.Join(root, tkHome("office")))
	if fi.Mode().Perm() != legacyStubMode {
		t.Fatalf("права заглушки: %v", fi.Mode())
	}

	out2, code := homeRun(t, root, "stub", tkHome("office"), bk)
	if code != 0 || out2 != out {
		t.Fatalf("повтор: %q %d", out2, code)
	}
	if got := readText(t, root, bk+tkHome("office")); got != tkScript {
		t.Fatal("повтор подменил копию заглушкой")
	}
}

func TestLegacyHomeStubRejects(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/passwd", "root:x:0:0\n")
	writeFixture(t, root, "home/a/b/vpn.sh", "#!/bin/bash\n")
	writeFixture(t, root, "home/c/real.sh", "#!/bin/bash\n")
	if err := os.Symlink(filepath.Join(root, "home/c/real.sh"), filepath.Join(root, tkHome("c"))); err != nil {
		t.Fatal(err)
	}
	bk := takeoverBackupRoot + "/takeover-20261020T101500Z"
	for _, tc := range [][]string{
		{"stub", "/etc/passwd", bk},
		{"stub", tkHome("a/b"), bk},
		{"stub", tkHome("c"), bk},
		{"stub", tkHome("../etc"), bk},
		{"stub", tkHome("c"), "/tmp/x"},
		{"stub", tkHome("c"), takeoverBackupRoot + "/takeover-x/../../../etc"},
		{"stub", tkHome("c")},
		{"scan", "x"},
		{"other"},
	} {
		if _, code := homeRun(t, root, tc...); code == 0 {
			t.Errorf("принято: %v", tc)
		}
	}
	if got := readText(t, root, "/etc/passwd"); got != "root:x:0:0\n" {
		t.Fatal("чужой файл тронут")
	}
	if fi, err := os.Lstat(filepath.Join(root, tkHome("c"))); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("ссылка тронута")
	}
}
