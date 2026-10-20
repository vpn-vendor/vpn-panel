package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/oswindow"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

var updatesChoiceFile = "/etc/vpn-panel/updates.json"

var (
	aptSourcePath     = "/etc/apt/sources.list.d/vpn-panel.sources"
	aptSourceTemplate = "/usr/share/vpn-panel/vpn-panel.sources"
	aptKeyring        = "/usr/share/keyrings/vpn-panel.asc"
)

type updatesChoice struct {
	Enabled bool   `json:"enabled"`
	At      string `json:"at"`
}

func readUpdatesChoice() (updatesChoice, bool) {
	raw, err := os.ReadFile(updatesChoiceFile)
	if err != nil {
		return updatesChoice{}, false
	}
	var c updatesChoice
	if json.Unmarshal(raw, &c) != nil {

		return updatesChoice{}, false
	}
	return c, true
}

func writeUpdatesChoice(enabled bool) error {
	raw, err := json.Marshal(updatesChoice{Enabled: enabled, At: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return durable.Write(updatesChoiceFile, append(raw, '\n'), 0o644)
}

func (u *updatesApplier) restoreOnStart() {
	u.mu.Lock()
	defer u.mu.Unlock()
	ensureAptSource()

	if c, chosen := readUpdatesChoice(); chosen && !c.Enabled {
		if fileExists(updatesConfPath) {
			if err := durable.Remove(updatesConfPath); err != nil {
				log.Printf("updates: settings not removed: %v", err)
			}
		}
		return
	}
	if u.tool() == "" {
		log.Printf("updates: unattended-upgrades is not installed, automatic updates are off")
		return
	}
	changed, err := durable.WriteIfChanged(updatesConfPath, []byte(updatesConf()), 0o644)
	if err != nil {
		log.Printf("updates: settings not written: %v", err)
		return
	}
	if changed || !upgradeTimerActive() {
		u.timers()
		log.Printf("updates: automatic updates are on")
	}
}

func enableUpdateTimers() {
	_ = exec.Command("systemctl", "enable", "--now", "apt-daily.timer").Run()
	_ = exec.Command("systemctl", "enable", "--now", "apt-daily-upgrade.timer").Run()
}

func ensureAptSource() {
	tpl, err := os.ReadFile(aptSourceTemplate)
	if err != nil || !fileExists(aptKeyring) || fileExists(aptSourcePath+".disabled") {
		return
	}
	codename := osCodename()
	if _, ok := oswindow.Find(codename); !ok {
		log.Printf("updates: release %q is outside the support window, update source not set", codename)
		return
	}
	if changed, err := durable.WriteIfChanged(aptSourcePath, aptSourceFor(tpl, codename), 0o644); err != nil {
		log.Printf("updates: update source not written: %v", err)
	} else if changed {
		log.Printf("updates: update source set for %s", codename)
	}
}

func aptSourceFor(tpl []byte, codename string) []byte {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(tpl), "\n"), "\n") {
		switch key, _, _ := strings.Cut(line, ":"); strings.TrimSpace(key) {
		case "Suites":
			out = append(out, "Suites: "+codename)
		case "Enabled":
		default:
			out = append(out, line)
		}
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

var osReleaseFile = "/etc/os-release"

func osCodename() string {
	raw, err := os.ReadFile(osReleaseFile)
	if err != nil {
		return ""
	}
	return sysinfo.ParseOSField(raw, "VERSION_CODENAME")
}
