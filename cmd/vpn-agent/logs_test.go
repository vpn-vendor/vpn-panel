package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeepTailOfKeepsWholeLastLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syslog")
	var buf bytes.Buffer
	for i := 0; buf.Len() < keepTail*3; i++ {
		buf.WriteString("2026-09-14 строка журнала номер ")
		buf.WriteString(string(rune('a' + i%26)))
		buf.WriteString(" xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if err := keepTailOf(path, st.Size()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) //nolint:gosec
	if len(got) >= keepTail || len(got) < keepTail/2 {
		t.Fatalf("хвост %d байт, ожидалось меньше %d и больше половины", len(got), keepTail)
	}
	if !bytes.HasPrefix(got, []byte("2026-09-14")) || !bytes.HasSuffix(got, []byte("\n")) {
		t.Fatal("хвост обязан начинаться с целой строки и кончаться переводом строки")
	}
	if !bytes.Equal(got, buf.Bytes()[len(buf.Bytes())-len(got):]) {
		t.Fatal("хвост не совпадает с концом исходного файла")
	}
}

func TestLogsTrimRejectsUnknownName(t *testing.T) {
	l := newLogsApplier()
	raw, _ := json.Marshal(map[string]any{"files": []string{"../../etc/passwd"}})
	if _, e := l.logsTrim(raw); e == nil || e.Code != codeLogsParams {
		t.Fatalf("чужой путь принят: %+v", e)
	}
	raw, _ = json.Marshal(map[string]any{"files": []string{"syslog", "dmesg"}})
	if _, e := l.logsTrim(raw); e == nil || e.Code != codeLogsParams {
		t.Fatalf("имя вне списка принято: %+v", e)
	}
}
