package main

import (
	"os"

	"github.com/vpn-vendor/vpn-panel-core/internal/console"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func installed(t *testing.T) map[string]bool {
	t.Helper()
	parts, err := filepath.Glob(filepath.Join("..", "..", "debian", "rules.d", "*.mk"))
	if err != nil || len(parts) == 0 {
		t.Fatal("нет частей сборки пакета")
	}
	target := regexp.MustCompile(`debian/vpn-panel(/[^\s\;]+)`)
	out := map[string]bool{}
	for _, part := range parts {
		data, err := os.ReadFile(part) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range target.FindAllStringSubmatch(string(data), -1) {
			out[m[1]] = true
		}
	}
	return out
}

func TestPackagePathsPointAtInstalledFiles(t *testing.T) {
	have := installed(t)
	ref := regexp.MustCompile(`/usr/(?:s?bin/vpn-[a-z-]+|libexec/vpn-panel/[a-z-]+)`)
	sources := []string{"debian/postinst", "debian/prerm", "debian/postrm", "cmd/vpn-agent/console.go", "scripts/lab/product.py"}
	for _, pattern := range []string{"debian/*.service", "debian/wrappers/*", "debian/assets/*.desktop", "debian/assets/*.policy", "debian/assets/ppp-*"} {
		found, _ := filepath.Glob(filepath.Join("..", "..", pattern))
		for _, f := range found {
			sources = append(sources, strings.TrimPrefix(filepath.ToSlash(f), "../../"))
		}
	}
	checked := 0
	for _, src := range sources {
		data, err := os.ReadFile(filepath.Join("..", "..", src)) //nolint:gosec
		if err != nil {
			continue
		}
		for _, path := range ref.FindAllString(string(data), -1) {
			checked++
			if !have[path] {
				t.Errorf("%s ссылается на %s, а пакет такого файла не кладёт", src, path)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("проверено ссылок: %d — тест ослеп", checked)
	}
}

func TestOnlyHumanCommandsAreOnThePath(t *testing.T) {
	var got []string
	for path := range installed(t) {
		if strings.HasPrefix(path, "/usr/sbin/") || strings.HasPrefix(path, "/usr/bin/") {
			got = append(got, path)
		}
	}
	sort.Strings(got)
	want := []string{"/usr/sbin/vpn-panel", "/usr/sbin/vpn-panel-backup-code", "/usr/sbin/vpn-panel-code",
		"/usr/sbin/vpn-panel-reset", "/usr/sbin/vpn-panel-support"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("в каталогах команд: %v\nожидалось: %v", got, want)
	}
}

func TestTabCompletionAsksTheCommand(t *testing.T) {
	text := readRepo(t, "debian/assets/vpn-panel.bash-completion")
	if !strings.Contains(text, "vpn-panel "+console.CompleteWord) || !strings.Contains(text, "complete -F _vpn_panel vpn-panel") {
		t.Error("подсказка TAB не спрашивает слова у команды")
	}
	have := installed(t)
	for _, path := range []string{"/usr/share/bash-completion/completions/vpn-panel", "/etc/update-motd.d/60-vpn-panel"} {
		if !have[path] {
			t.Errorf("пакет не кладёт %s", path)
		}
	}
	if !strings.Contains(readRepo(t, "debian/assets/motd-vpn-panel"), "sudo vpn-panel") {
		t.Error("строка при входе на сервер не называет команду")
	}
}

func TestHumanCommandStillServesTheSystem(t *testing.T) {
	text := readRepo(t, "debian/wrappers/vpn-panel")
	for _, want := range []string{`"${1:-}" = artisan`, `[ ! -t 0 ]`, `exec "$SERVER" "$@"`, `exec "$SERVICE" console "$@"`, `sudo vpn-panel`,
		"help|--help|-h|" + console.CompleteWord + ")"} {
		if !strings.Contains(text, want) {
			t.Errorf("в команде vpn-panel нет %q", want)
		}
	}
	for _, unit := range []string{"debian/vpn-panel.vpn-panel.service", "debian/vpn-panel.vpn-agent.service"} {
		if strings.Contains(readRepo(t, unit), "ExecStart=/usr/sbin/") {
			t.Errorf("%s запускается через команду человека: ошибка в ней остановила бы службу", unit)
		}
	}
}
