package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const legacyStubScript = `#!/bin/sh
# Старый скрипт выключен: сервером управляет панель VPN Panel.
echo "Этот сервер теперь работает на панели VPN Panel."
echo "Старый скрипт vpn.sh выключен, его копия лежит в резервной копии панели."
echo "Настройки открываются в браузере по адресу шлюза."
exit 1
`

const legacyStubMode = 0o755

func runLegacyHome(args []string) int { return legacyHome("/", args, os.Stdout, os.Stderr) }

func legacyHome(root string, args []string, out, errOut io.Writer) int {
	fail := func(err error) int {
		_, _ = fmt.Fprintln(errOut, "legacy-home:", err)
		return 1
	}
	switch {
	case len(args) == 1 && args[0] == "scan":
		data, err := json.Marshal(homeScriptsIn(root))
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, string(data))
		return 0
	case len(args) == 3 && args[0] == "stub":
		entry, err := stubHomeScript(root, args[1], args[2])
		if err != nil {
			return fail(err)
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, string(data))
		return 0
	}
	return fail(errors.New("использование: legacy-home scan | legacy-home stub <путь> <каталог копии>"))
}

func homeScriptsIn(root string) []string {
	candidates := []string{"/root/" + legacyvpn.ScriptName}
	if ents, err := os.ReadDir(filepath.Join(root, "home")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				candidates = append(candidates, "/home/"+e.Name()+"/"+legacyvpn.ScriptName)
			}
		}
	}
	out := []string{}
	for _, p := range candidates {
		if fi, err := os.Lstat(filepath.Join(root, p)); err == nil && fi.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}

func parseHomeScan(data []byte) ([]string, error) {
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil {
		return nil, fmt.Errorf("ответ не разобран: %w", err)
	}
	for _, p := range paths {
		if !homeScriptPath(p) {
			return nil, fmt.Errorf("путь %q не сценарий в домашнем каталоге", p)
		}
	}
	return paths, nil
}

func homeScriptPath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || filepath.Base(p) != legacyvpn.ScriptName {
		return false
	}
	parts := strings.Split(strings.Trim(filepath.Dir(p), "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "root":
		return true
	case len(parts) == 2 && parts[0] == "home" && parts[1] != "":
		return true
	}
	return false
}

func backupDirPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && filepath.Dir(p) == takeoverBackupRoot &&
		strings.HasPrefix(filepath.Base(p), takeoverBackupPrefix)
}

func stubHomeScript(root, logical, backupDir string) (takeoverCopy, error) {
	if !homeScriptPath(logical) {
		return takeoverCopy{}, fmt.Errorf("путь %q не сценарий в домашнем каталоге", logical)
	}
	if !backupDirPath(backupDir) {
		return takeoverCopy{}, fmt.Errorf("каталог %q не каталог резервной копии", backupDir)
	}
	path := filepath.Join(root, logical)
	fi, err := os.Lstat(path) //nolint:gosec
	if err != nil {
		return takeoverCopy{}, err
	}
	if !fi.Mode().IsRegular() {
		return takeoverCopy{}, fmt.Errorf("%s: не обычный файл", logical)
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return takeoverCopy{}, err
	}
	uid, gid := fileOwner(fi)
	dup := filepath.Join(root, backupDir, logical)
	if bytes.Equal(data, []byte(legacyStubScript)) {

		saved, err := os.ReadFile(dup) //nolint:gosec
		if err != nil {
			return takeoverCopy{}, fmt.Errorf("%s: заглушка на месте, а копии нет", logical)
		}
		cfi, err := os.Lstat(dup) //nolint:gosec
		if err != nil {
			return takeoverCopy{}, err
		}
		cuid, cgid := fileOwner(cfi)
		return takeoverCopy{Path: logical, Mode: uint32(cfi.Mode().Perm()), UID: cuid, GID: cgid, SHA256: sha256Hex(saved)}, nil
	}
	entry := takeoverCopy{Path: logical, Mode: uint32(fi.Mode().Perm()), UID: uid, GID: gid, SHA256: sha256Hex(data)}
	if cur, err := os.ReadFile(dup); err != nil || !bytes.Equal(cur, data) { //nolint:gosec
		if err := durable.MkdirAll(filepath.Dir(dup), 0o700); err != nil {
			return takeoverCopy{}, err
		}
		if err := durable.Write(dup, data, fi.Mode().Perm(), durable.Owner(uid, gid)); err != nil {
			return takeoverCopy{}, err
		}
	}
	if err := durable.Write(path, []byte(legacyStubScript), fs.FileMode(legacyStubMode), durable.Owner(uid, gid)); err != nil {
		return takeoverCopy{}, err
	}
	return entry, nil
}
