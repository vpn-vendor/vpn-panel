package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/policy"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
)

func TestQoSGateSuppressesApply(t *testing.T) {
	q := newQosApplier()
	q.policy = fakePolicy{flags: map[string]bool{policy.FlagQoSOff: true}}
	q.mu.Lock()
	changed, aerr := q.applyPlan(qosgen.Plan{Enabled: true, WAN: "ens0", DownKbit: 100000, UpKbit: 50000})
	q.mu.Unlock()
	if aerr != nil {
		t.Fatalf("ворота не должны давать ошибку: %v", aerr)
	}
	if changed {
		t.Error("при активном qos-off очередь не должна ставиться")
	}
}

func TestQoSGateOpenWithoutPolicy(t *testing.T) {
	q := newQosApplier()
	if q.suppressed() {
		t.Error("без политики жгут не может быть активен")
	}
}

func TestUpdatesPauseWritesAndClears(t *testing.T) {
	old := updatesPauseConfPath
	updatesPauseConfPath = filepath.Join(t.TempDir(), "53vpn-panel-policy")
	t.Cleanup(func() { updatesPauseConfPath = old })

	u := newUpdatesApplier()
	on := fakePolicy{flags: map[string]bool{policy.FlagUpdatesPause: true}}
	off := fakePolicy{flags: map[string]bool{}}

	u.policy = on
	u.onPolicyChange()
	data, err := os.ReadFile(updatesPauseConfPath) //nolint:gosec
	if err != nil {
		t.Fatalf("файл паузы не создан: %v", err)
	}
	if !strings.Contains(string(data), `APT::Periodic::Unattended-Upgrade "0";`) {
		t.Errorf("файл паузы не гасит периодический запуск:\n%s", data)
	}

	u.onPolicyChange()
	if _, err := os.Stat(updatesPauseConfPath); err != nil {
		t.Errorf("повторная сверка убрала файл паузы: %v", err)
	}

	u.policy = off
	u.onPolicyChange()
	if _, err := os.Stat(updatesPauseConfPath); !os.IsNotExist(err) {
		t.Error("снятие флага не убрало файл паузы")
	}

	u.onPolicyChange()
}

func TestUpdatesPauseSortsAfterAutoFile(t *testing.T) {
	if updatesPauseConfPath <= updatesConfPath {
		t.Fatalf("файл паузы %s читается не позже настройки %s — пауза не сработает",
			updatesPauseConfPath, updatesConfPath)
	}
}
