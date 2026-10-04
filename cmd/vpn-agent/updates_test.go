package main

import (
	"os"
	"strings"
	"testing"
)

func TestUpdatesConfClearsSystemOrigins(t *testing.T) {
	conf := updatesConf()
	clearAllowed := strings.Index(conf, "#clear Unattended-Upgrade::Allowed-Origins")
	clearPattern := strings.Index(conf, "#clear Unattended-Upgrade::Origins-Pattern")
	ours := strings.Index(conf, `"origin=VPN Vendor,codename=resolute"`)
	if clearAllowed < 0 || clearPattern < 0 {
		t.Fatalf("в настройке нет очистки системных источников:\n%s", conf)
	}
	if ours < 0 {
		t.Fatalf("в настройке нет нашего источника:\n%s", conf)
	}
	if ours < clearAllowed || ours < clearPattern {
		t.Fatalf("наш источник вписан ДО очистки — очистка его же и сотрёт:\n%s", conf)
	}
}

func TestUpdatesConfNeverReboots(t *testing.T) {
	conf := updatesConf()
	for _, want := range []string{
		`Unattended-Upgrade::Automatic-Reboot "false";`,
		`Unattended-Upgrade::Automatic-Reboot-WithUsers "false";`,
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("в настройке нет запрета самостоятельной перезагрузки (%s)", want)
		}
	}
}

func TestUpdatesConfSortsAfterSystemFile(t *testing.T) {
	if updatesConfPath <= "/etc/apt/apt.conf.d/50unattended-upgrades" {
		t.Fatalf("наш файл %s читается раньше штатного — очистка не сработает", updatesConfPath)
	}
}

func TestAptConfIsWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/52vpn-panel-auto"
	if err := writeAptConf(path, "// проверка\n"); err != nil {
		t.Fatalf("запись не удалась: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("файла нет: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("права %v, а apt должен читать файл и от имени _apt (нужно 0644)", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Fatalf("временный файл остался рядом с настройкой")
	}
}
