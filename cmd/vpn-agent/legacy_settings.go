package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	legacySourceLive   = "live"
	legacySourceBackup = "backup"

	legacySecretSource = "legacy"
)

func (r *takeoverRunner) legacyRoot() (root, source string) {
	j, exists, err := r.readJournal()
	if err == nil && exists && j.Backup != "" {
		switch j.Stage {
		case takeover.StageFinishing, takeover.StagePartial, takeover.StageDone:
			return r.p(j.Backup), legacySourceBackup
		}
	}
	return r.sys.root, legacySourceLive
}

func (r *takeoverRunner) legacyFound(source string) bool {
	if source == legacySourceBackup {
		j, exists, err := r.readJournal()
		if err != nil || !exists {
			return false
		}
		for _, it := range j.Plan.Items {
			if strings.HasPrefix(it.ID, "legacy.") {
				return true
			}
		}
		return false
	}
	return r.legacyReport(nil).Gateway
}

func (r *takeoverRunner) legacySettingsStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	root, source := r.legacyRoot()
	found := r.legacyFound(source)
	res := map[string]any{"found": found, "source": source}
	if found {
		res["settings"] = legacyvpn.ReadSettings(root)
	}
	return res, nil
}

func (r *takeoverRunner) legacyPPPoEPassword(user string) (string, bool) {
	root, _ := r.legacyRoot()
	return legacyvpn.ReadPPPoEPassword(root, user)
}

func legacyVPNConfig(root, protocol string) (string, error) {
	path := legacyvpn.VPNConfigPath(protocol)
	if path == "" {
		return "", errors.New("у старого шлюза нет подключения этого протокола")
	}
	fi, err := os.Lstat(filepath.Join(root, path))
	if err != nil || !fi.Mode().IsRegular() {
		return "", errors.New("файла подключения старого шлюза нет")
	}
	if fi.Size() > vpndriver.MaxConfigBytes {
		return "", fmt.Errorf("файл подключения старого шлюза слишком велик")
	}
	data, err := os.ReadFile(filepath.Join(root, path)) //nolint:gosec
	if err != nil {
		return "", err
	}
	return string(data), nil
}
