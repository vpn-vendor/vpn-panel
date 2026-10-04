package main

import (
	"encoding/json"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const (
	codeUpdParams = 1801
	codeUpdWrite  = 1802
	codeUpdNoTool = 1803
)

const updatesConfPath = "/etc/apt/apt.conf.d/52vpn-panel-auto"

const (
	updatesOrigin   = "VPN Vendor"
	updatesCodename = "resolute"
)

type updatesApplier struct {
	mu sync.Mutex
}

func newUpdatesApplier() *updatesApplier { return &updatesApplier{} }

func updatesConf() string {
	return fmt.Sprintf(`// Автоматические обновления панели управления шлюзом.
// Файл создаёт панель по команде владельца; правка руками не нужна.
//
// Очистка списков обязательна: без неё к нашему источнику добавились бы
// системные, и «обновлять панель» тихо превратилось бы в «обновлять всё».
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern { "origin=%s,codename=%s"; };

// Перезагрузку система не выбирает сама никогда: шлюз с офисом за спиной
// не имеет права уйти в перезагрузку по своему усмотрению.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Ежедневно: обновить список и поставить то, что разрешено выше.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`, updatesOrigin, updatesCodename)
}

type updatesStatus struct {
	Enabled     bool   `json:"enabled"`
	ToolPresent bool   `json:"tool_present"`
	TimerActive bool   `json:"timer_active"`
	Version     string `json:"version"`
	LastRun     string `json:"last_run"`
	LastResult  string `json:"last_result"`
}

func (u *updatesApplier) updatesStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	st := updatesStatus{
		Enabled:     fileExists(updatesConfPath),
		ToolPresent: unattendedTool() != "",
		TimerActive: upgradeTimerActive(),
		Version:     installedVersion(),
	}
	st.LastRun, st.LastResult = lastUnattendedRun()
	return st, nil
}

type updatesSetParams struct {
	Enabled *bool `json:"enabled"`
}

func (u *updatesApplier) updatesSet(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p updatesSetParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &agentrpc.ErrorObject{Code: codeUpdParams,
				Message: "запрос составлен неверно"}
		}
	}
	if p.Enabled == nil {
		return nil, &agentrpc.ErrorObject{Code: codeUpdParams,
			Message: "не указано, включать автообновления или выключать"}
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if !*p.Enabled {
		if err := durable.Remove(updatesConfPath); err != nil {
			return nil, &agentrpc.ErrorObject{Code: codeUpdWrite,
				Message: "не удалось выключить автоматические обновления"}
		}
		return u.updatesStatus(nil)
	}

	if unattendedTool() == "" {
		return nil, &agentrpc.ErrorObject{Code: codeUpdNoTool,
			Message: "в системе нет службы автоматических обновлений — панель не может включить их сама",
			Data:    map[string]any{"recoverable": true}}
	}
	if err := writeAptConf(updatesConfPath, updatesConf()); err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeUpdWrite,
			Message: "не удалось записать настройку обновлений"}
	}

	_ = exec.Command("systemctl", "enable", "--now", "apt-daily.timer").Run()
	_ = exec.Command("systemctl", "enable", "--now", "apt-daily-upgrade.timer").Run()
	return u.updatesStatus(nil)
}

func writeAptConf(path, body string) error {
	return durable.Write(path, []byte(body), 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func unattendedTool() string {
	for _, p := range []string{"/usr/bin/unattended-upgrade", "/usr/bin/unattended-upgrades"} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func upgradeTimerActive() bool {
	out, _ := exec.Command("systemctl", "is-active", "apt-daily-upgrade.timer").Output()
	return strings.TrimSpace(string(out)) == "active"
}

func installedVersion() string {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "vpn-panel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func lastUnattendedRun() (when string, result string) {
	const logPath = "/var/log/unattended-upgrades/unattended-upgrades.log"
	info, err := os.Stat(logPath)
	if err != nil {
		return "", ""
	}
	when = info.ModTime().Format(time.RFC3339)
	data, err := os.ReadFile(logPath)
	if err != nil {
		return when, ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i := len(lines) - 1; i >= 0 && i > len(lines)-40; i-- {
		if strings.Contains(lines[i], "Packages that will be upgraded") ||
			strings.Contains(lines[i], "All upgrades installed") ||
			strings.Contains(lines[i], "No packages found") {
			return when, strings.TrimSpace(lines[i])
		}
	}
	return when, strings.TrimSpace(lines[len(lines)-1])
}
