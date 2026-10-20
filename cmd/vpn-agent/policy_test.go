package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/policy"
)

func tempState(t *testing.T) {
	t.Helper()
	old := policyStatePath
	policyStatePath = filepath.Join(t.TempDir(), "policy.json")
	t.Cleanup(func() { policyStatePath = old })
}

func goodDoc() []byte {
	return []byte(`{"schema":1,"flags":{"qos-off":true},"advisory":{"pull_now":true,"message":"тест"}}`)
}

func testApplier(dl func(string) ([]byte, error), vf func(doc, sig []byte) error) *policyApplier {
	return &policyApplier{current: policy.Default(), stop: make(chan struct{}), download: dl, verify: vf}
}

func TestFetchOnceApplies(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) {
		if strings.HasSuffix(url, ".asc") {
			return []byte("sig"), nil
		}
		return goodDoc(), nil
	}, func(doc, sig []byte) error { return nil })
	changed, err := pa.fetchOnce()
	if err != nil {
		t.Fatalf("fetchOnce: %v", err)
	}
	if !changed {
		t.Error("первый документ должен считаться изменением")
	}
	if !pa.get().Bool("qos-off") {
		t.Error("флаг qos-off не применился")
	}
}

func TestFetchOnceRejectsBadSig(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) { return goodDoc(), nil },
		func(doc, sig []byte) error { return errors.New("подпись чужая") })
	if _, err := pa.fetchOnce(); err == nil {
		t.Fatal("документ с чужой подписью применён")
	}
	if pa.get().Bool("qos-off") {
		t.Error("при плохой подписи политика не должна меняться")
	}
	if _, serr := os.Stat(policyStatePath); serr == nil {
		t.Error("непроверенный документ не должен попадать на диск")
	}
}

func TestFetchOnceDownloadError(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) { return nil, errors.New("нет сети") },
		func(doc, sig []byte) error { return nil })
	if _, err := pa.fetchOnce(); err == nil {
		t.Fatal("ошибка сети проглочена")
	}
}

func TestBackoffCaps(t *testing.T) {
	if got := backoff(policyMaxInterval); got != policyMaxInterval {
		t.Errorf("отступ превысил максимум: %v", got)
	}
}

func TestPolicyStatusDTO(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) {
		if strings.HasSuffix(url, ".asc") {
			return []byte("sig"), nil
		}
		return goodDoc(), nil
	}, func(doc, sig []byte) error { return nil })
	if _, err := pa.fetchOnce(); err != nil {
		t.Fatal(err)
	}
	res, rpcErr := pa.policyStatus(nil)
	if rpcErr != nil {
		t.Fatalf("policyStatus: %v", rpcErr)
	}
	dto := res.(policyStatusDTO)
	byName := map[string]policyFlagDTO{}
	for _, f := range dto.Flags {
		byName[f.Name] = f
	}
	if !byName[policy.FlagQoSOff].On {
		t.Error("DTO не отразил qos-off")
	}
	if byName[policy.FlagQoSOff].Why == "" {
		t.Error("DTO должен нести человеческий текст флага из реестра")
	}
	if _, ok := byName[policy.FlagUpdatesPause]; !ok {
		t.Error("DTO должен перечислять все объявленные флаги, даже невключённые")
	}
	if !dto.Advisory.PullNow {
		t.Error("advisory не в DTO")
	}
}

type fakePolicy struct{ flags map[string]bool }

func (f fakePolicy) Flag(name string) bool { return f.flags[name] }

func TestPolicyApplierFlag(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) {
		if strings.HasSuffix(url, ".asc") {
			return []byte("sig"), nil
		}
		return goodDoc(), nil
	}, func(doc, sig []byte) error { return nil })
	if _, err := pa.fetchOnce(); err != nil {
		t.Fatal(err)
	}
	if !pa.Flag(policy.FlagQoSOff) {
		t.Error("Flag не вернул включённый qos-off")
	}
	if pa.Flag(policy.FlagUpdatesPause) {
		t.Error("Flag вернул невключённый флаг как включённый")
	}
}

func TestReconcileRunsEveryPoll(t *testing.T) {
	tempState(t)
	pa := testApplier(func(url string) ([]byte, error) {
		if strings.HasSuffix(url, ".asc") {
			return []byte("sig"), nil
		}
		return goodDoc(), nil
	}, func(doc, sig []byte) error { return nil })
	calls := 0
	pa.OnChange(func() { calls++ })

	if _, err := pa.fetchOnce(); err != nil {
		t.Fatal(err)
	}
	pa.reconcile()
	if _, err := pa.fetchOnce(); err != nil {
		t.Fatal(err)
	}
	pa.reconcile()
	if calls != 2 {
		t.Errorf("реконсиляция должна была сработать на каждом опросе, а сработала %d раз", calls)
	}
}

func TestLoadLastGood(t *testing.T) {
	tempState(t)
	if err := os.WriteFile(policyStatePath, goodDoc(), 0o600); err != nil {
		t.Fatal(err)
	}
	pa := newPolicyApplier()
	if !pa.get().Bool("qos-off") {
		t.Error("последняя хорошая политика не поднялась при старте")
	}
}
