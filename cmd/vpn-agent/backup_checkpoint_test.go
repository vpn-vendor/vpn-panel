package main

import (
	"bytes"
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"os"
	"path/filepath"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

func withCheckpointFile(t *testing.T) string {
	t.Helper()
	saved := checkpointFile
	checkpointFile = filepath.Join(t.TempDir(), "import-checkpoint.json")
	t.Cleanup(func() { checkpointFile = saved })
	return checkpointFile
}

func TestCheckpointLifecycle(t *testing.T) {
	path := withCheckpointFile(t)
	b, got := testBackup(t)
	var pruned []backupSecrets
	b.prune = func(s backupSecrets) (map[string]any, *agentrpc.ErrorObject) {
		pruned = append(pruned, s)
		return map[string]any{"removed": []string{}}, nil
	}
	doc := copyDocument(t, backupfile.KindCopy)
	if _, aerr := call(t, b.backupCheckpoint, map[string]any{"document": doc}); aerr != nil {
		t.Fatal(aerr)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("точка возврата: %v %v", fi, err)
	}
	if _, aerr := call(t, b.backupCheckpoint, map[string]any{"document": doc}); aerr == nil || aerr.Code != codeBackupPending {
		t.Fatalf("вторая точка поверх незавершённого импорта: %v", aerr)
	}
	if st, _ := call(t, b.backupCheckpointStatus, map[string]any{}); string(st["exists"]) != "true" {
		t.Fatalf("состояние: %v", st)
	}
	var want, have bytes.Buffer
	d, _ := call(t, b.backupCheckpointDocument, map[string]any{})
	if json.Compact(&want, doc) != nil || json.Compact(&have, d["document"]) != nil || want.String() != have.String() {
		t.Fatalf("документ точки: %s", d["document"])
	}
	if _, aerr := call(t, b.backupCheckpointSecrets, map[string]any{}); aerr != nil {
		t.Fatal(aerr)
	}
	if len(*got) != 1 || len((*got)[0].choice.Profiles) != 1 || !(*got)[0].choice.PPPoE {
		t.Fatalf("возврат секретов точки: %+v", *got)
	}
	if _, aerr := call(t, b.backupCheckpointSecrets, map[string]any{"prune": true}); aerr != nil || len(pruned) != 1 || len(pruned[0].Profiles) != 1 {
		t.Fatalf("уборка лишних профилей: %v %+v", aerr, pruned)
	}
	if _, aerr := call(t, b.backupCheckpointDrop, map[string]any{}); aerr != nil {
		t.Fatal(aerr)
	}
	if st, _ := call(t, b.backupCheckpointStatus, map[string]any{}); string(st["exists"]) != "false" {
		t.Fatalf("после подтверждения точки быть не должно: %v", st)
	}
}

func TestCheckpointRefusesTemplate(t *testing.T) {
	withCheckpointFile(t)
	b, _ := testBackup(t)
	if _, aerr := call(t, b.backupCheckpoint, map[string]any{"document": copyDocument(t, backupfile.KindTemplate)}); aerr == nil || aerr.Code != codeBackupFile {
		t.Fatalf("точка возврата из шаблона: %v", aerr)
	}
}

type pruneDriver struct {
	unknownDriver
	profiles []string
	removed  []string
}

func (d *pruneDriver) listProfiles() []string { return d.profiles }
func (d *pruneDriver) removeProfile(slug string, _ bool) error {
	d.removed = append(d.removed, slug)
	return nil
}

func TestPruneRemovesOnlyExtraProfiles(t *testing.T) {
	d := &pruneDriver{profiles: []string{"office", "extra"}}
	v := &vpnApplier{drivers: map[vpndriver.Protocol]tunnelDriver{"wireguard": d}}
	keep := backupSecrets{Profiles: []secretProfile{{Protocol: "wireguard", Slug: "office"}}}
	if _, aerr := v.pruneSecrets(keep); aerr != nil {
		t.Fatal(aerr)
	}
	if len(d.removed) != 1 || d.removed[0] != "extra" {
		t.Fatalf("убрано %v, ждали только extra", d.removed)
	}
}

func TestCheckpointStatusBroken(t *testing.T) {
	dir := t.TempDir()
	old := checkpointFile
	checkpointFile = filepath.Join(dir, "import-checkpoint.json")
	t.Cleanup(func() { checkpointFile = old })
	if err := os.WriteFile(checkpointFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := testBackup(t)
	m, aerr := call(t, b.backupCheckpointStatus, map[string]any{})
	if aerr != nil || string(m["exists"]) != "true" || string(m["broken"]) != "true" {
		t.Fatalf("повреждённая точка: %v %+v", m, aerr)
	}
	if _, aerr := call(t, b.backupCheckpointDrop, map[string]any{}); aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := os.Stat(checkpointFile); !os.IsNotExist(err) {
		t.Fatal("повреждённая точка не снята")
	}
}

func TestWriteSecretDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	if err := durable.Write(path, []byte("ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	data, _ := os.ReadFile(path) //nolint:gosec
	if err != nil || st.Mode().Perm() != 0o600 || string(data) != "ключ" {
		t.Fatalf("%v %v %q", err, st.Mode(), data)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("временный файл остался")
	}
}
