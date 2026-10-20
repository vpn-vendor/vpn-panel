package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempUpdates(t *testing.T, tool string) (*updatesApplier, *int) {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldChoice, oldSrc, oldTpl, oldKey, oldOS := updatesConfPath, updatesChoiceFile,
		aptSourcePath, aptSourceTemplate, aptKeyring, osReleaseFile
	t.Cleanup(func() {
		updatesConfPath, updatesChoiceFile, aptSourcePath, aptSourceTemplate, aptKeyring, osReleaseFile =
			oldConf, oldChoice, oldSrc, oldTpl, oldKey, oldOS
	})
	updatesConfPath = filepath.Join(dir, "52vpn-panel-auto")
	updatesChoiceFile = filepath.Join(dir, "updates.json")
	aptSourcePath = filepath.Join(dir, "vpn-panel.sources")
	aptSourceTemplate = filepath.Join(dir, "template.sources")
	aptKeyring = filepath.Join(dir, "vpn-panel.asc")
	osReleaseFile = filepath.Join(dir, "os-release")
	timers := 0
	return &updatesApplier{tool: func() string { return tool }, timers: func() { timers++ }}, &timers
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

func TestUpdatesOnByDefault(t *testing.T) {
	u, timers := tempUpdates(t, "/usr/bin/unattended-upgrade")
	u.restoreOnStart()
	if !fileExists(updatesConfPath) || *timers != 1 {
		t.Fatalf("умолчание — включено: файл %v, таймеры %d", fileExists(updatesConfPath), *timers)
	}

	before, _ := os.Stat(updatesConfPath)
	u.restoreOnStart()
	after, _ := os.Stat(updatesConfPath)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("настройка переписана без изменений")
	}
}

func TestUpdatesOffStaysOff(t *testing.T) {
	u, timers := tempUpdates(t, "/usr/bin/unattended-upgrade")
	write(t, updatesConfPath, "старая настройка\n")
	if err := writeUpdatesChoice(false); err != nil {
		t.Fatal(err)
	}
	u.restoreOnStart()
	if fileExists(updatesConfPath) || *timers != 0 {
		t.Fatal("выбор «выключено» обязан пережить старт агента")
	}
}

func TestBrokenChoiceKeepsDefault(t *testing.T) {
	u, _ := tempUpdates(t, "/usr/bin/unattended-upgrade")
	write(t, updatesChoiceFile, "{не json")
	u.restoreOnStart()
	if !fileExists(updatesConfPath) {
		t.Fatal("испорченный выбор — это не «выключено»")
	}
}

func TestUpdatesNeedTheTool(t *testing.T) {
	u, timers := tempUpdates(t, "")
	u.restoreOnStart()
	if fileExists(updatesConfPath) || *timers != 0 {
		t.Fatal("без службы автообновлений настройку писать незачем")
	}
}

const sourceTemplate = "Types: deb\nURIs: https://example.invalid/repo\nSuites: @CODENAME@\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/vpn-panel.asc\n"

func TestAptSourceFollowsRelease(t *testing.T) {
	tempUpdates(t, "")
	write(t, aptSourceTemplate, sourceTemplate)
	write(t, aptKeyring, "ключ")
	write(t, osReleaseFile, "VERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n")
	ensureAptSource()
	got, _ := os.ReadFile(aptSourcePath) //nolint:gosec
	if !strings.Contains(string(got), "Suites: jammy\n") || strings.Contains(string(got), "@CODENAME@") {
		t.Fatalf("источник 22.04:\n%s", got)
	}

	write(t, aptSourcePath, string(got)+"Enabled: no\n")
	write(t, osReleaseFile, "VERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n")
	ensureAptSource()
	got, _ = os.ReadFile(aptSourcePath) //nolint:gosec
	if !strings.Contains(string(got), "Suites: resolute\n") || strings.Contains(string(got), "Enabled") {
		t.Fatalf("источник после обновления системы:\n%s", got)
	}
}

func TestAptSourceRespectsOptOutAndWindow(t *testing.T) {
	tempUpdates(t, "")
	write(t, aptSourceTemplate, sourceTemplate)
	write(t, aptKeyring, "ключ")
	write(t, osReleaseFile, "VERSION_CODENAME=noble\n")
	ensureAptSource()
	if fileExists(aptSourcePath) {
		t.Fatal("выпуска нет в окне поддержки — источник не ставится")
	}
	write(t, osReleaseFile, "VERSION_CODENAME=jammy\n")
	write(t, aptSourcePath+".disabled", "отключён администратором\n")
	ensureAptSource()
	if fileExists(aptSourcePath) {
		t.Fatal("отключённый администратором источник не возвращается")
	}
	if err := os.Remove(aptSourcePath + ".disabled"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(aptKeyring); err != nil {
		t.Fatal(err)
	}
	ensureAptSource()
	if fileExists(aptSourcePath) {
		t.Fatal("без ключа проверки источник не ставится")
	}
}
