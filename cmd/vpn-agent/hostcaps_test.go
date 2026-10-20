package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type fakePassport struct {
	*hostPassport
	runs    int
	answer  hostcaps.Answer
	version string
	saved   []byte
}

func newFakePassport() *fakePassport {
	f := &fakePassport{answer: hostcaps.Yes, version: "2.5.11"}
	f.hostPassport = &hostPassport{
		limiter:  ratelimit.New(2, 1, time.Minute),
		versions: func([]string) map[string]string { return map[string]string{"openvpn": f.version} },
		probes: []hostProbe{{ids: []string{"openvpn.dns_updown"}, run: func(context.Context) []hostcaps.Fact {
			f.runs++
			return []hostcaps.Fact{{ID: "openvpn.dns_updown", Class: hostcaps.ClassFeature, Answer: f.answer}}
		}}},
		readFile: func() ([]byte, error) {
			if f.saved == nil {
				return nil, errors.New("кэша нет")
			}
			return f.saved, nil
		},
		write: func(b []byte) error { f.saved = b; return nil },
		now:   func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) },
	}
	return f
}

func TestPassportCacheIsReusedUntilInputsChange(t *testing.T) {
	f := newFakePassport()
	f.loadCache()
	if !f.stale() {
		t.Fatal("без кэша паспорт обязан считаться устаревшим")
	}
	f.probeNow()
	if f.current().TakenAt != "2026-10-19T12:00:00Z" || f.current().Answer("openvpn.dns_updown") != hostcaps.Yes {
		t.Fatalf("снимок %+v", f.current())
	}

	again := newFakePassport()
	again.saved = f.saved
	again.loadCache()
	if again.stale() {
		t.Fatal("кэш с теми же входами обязан приниматься без проб")
	}

	again.version = "2.7.0"
	if !again.stale() {
		t.Fatal("смена версии программы не устарила паспорт")
	}
}

func TestPassportWithUnknownIsStale(t *testing.T) {
	f := newFakePassport()
	f.answer = hostcaps.Unknown
	f.probeNow()
	if !f.stale() {
		t.Fatal("паспорт с «неизвестно» обязан сниматься заново при удобном случае")
	}
}

func TestPassportOfOtherSchemaIsIgnored(t *testing.T) {
	f := newFakePassport()
	raw, _ := json.Marshal(hostcaps.Snapshot{Schema: hostcaps.Schema + 1, Digest: "x"})
	f.saved = raw
	f.loadCache()
	if f.current().Digest != "" {
		t.Fatal("снимок чужой схемы не должен читаться")
	}
}

func TestRecheckIsBounded(t *testing.T) {
	f := newFakePassport()
	used := f.probeNow()
	if f.recheck("другой отпечаток") != true || f.runs != 1 {
		t.Fatal("паспорт уже новее конфига — пробовать заново не нужно")
	}
	if f.recheck(used) || f.runs != 2 {
		t.Fatalf("факты не изменились — ответ «нет», проба одна (проб %d)", f.runs)
	}
	f.answer = hostcaps.No
	if !f.recheck(used) || f.runs != 3 {
		t.Fatalf("факты изменились — ответ «да» (проб %d)", f.runs)
	}
	if f.recheck(f.current().Digest) || f.runs != 3 {
		t.Fatalf("ограничитель обязан остановить новые пробы (проб %d)", f.runs)
	}
}

func TestRefreshStartsOnlyWhenStaleAndIsLimited(t *testing.T) {
	f := newFakePassport()
	f.probeNow()
	res, aerr := f.passportRefresh(nil)
	if aerr != nil || res.(map[string]any)["started"] != false {
		t.Fatalf("свежий паспорт не переснимается: %v %v", res, aerr)
	}
	_, _ = f.passportRefresh(nil)
	_, aerr = f.passportRefresh(nil)
	if aerr == nil || aerr.Code != codeHostBusy {
		t.Fatalf("третий вызов подряд обязан упереться в ограничитель: %+v", aerr)
	}
}

func TestPassportStatusIsNeverNull(t *testing.T) {
	f := newFakePassport()
	res, _ := f.passportStatus(nil)
	raw, _ := json.Marshal(res)
	for _, want := range []string{`"facts":[]`, `"versions":{}`, `"probing":false`, `"taken_at":""`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("в ответе нет %s: %s", want, raw)
		}
	}
}

func TestProbeSetIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range hostProbeSet() {
		for _, id := range p.ids {
			if seen[id] {
				t.Errorf("факт %s снимают две пробы", id)
			}
			seen[id] = true
		}
	}
	for _, want := range []string{"nft.ruleset", "kea.socket_retry", "kernel.cake", "netplan.try", "os.codename"} {
		if !seen[want] {
			t.Errorf("факт %s никто не снимает", want)
		}
	}
}

func TestSpoilersBreakConfigs(t *testing.T) {
	kea := spoilKea([]byte(`{"Dhcp4":{"valid-lifetime":3600}}`))
	if !strings.Contains(string(kea), `"vp-probe-unknown-key":1`) {
		t.Fatalf("порча Kea не добавила ключ: %s", kea)
	}
	if got := string(spoilKea([]byte("не json"))); !strings.HasSuffix(got, "{") {
		t.Fatalf("сломанный конфиг обязан остаться сломанным: %s", got)
	}
	if got := string(appendLine("vp-probe-unknown-option")([]byte("client\n"))); got != "client\nvp-probe-unknown-option\n" {
		t.Fatalf("порча строкой: %q", got)
	}
}

func TestVerdictSeparatesRejectionFromFailure(t *testing.T) {
	ctx := context.Background()
	exitErr := exec.Command("false").Run()
	if err := verdict(ctx, []byte("Options error: x\nUse --help"), exitErr); !hostcaps.IsRejected(err) ||
		!strings.Contains(err.Error(), "Options error: x") {
		t.Fatalf("отказ программы: %v", err)
	}
	if err := verdict(ctx, nil, errors.New("программы нет")); hostcaps.IsRejected(err) {
		t.Fatal("незапуск программы — не отказ")
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := verdict(done, nil, exitErr); hostcaps.IsRejected(err) {
		t.Fatal("убитая по сроку проверка — не отказ")
	}
}

func TestUpstreamVersion(t *testing.T) {
	for in, want := range map[string]string{
		"2.5.11-0ubuntu0.22.04.5": "2.5.11", "1:2.7.0-1ubuntu1": "2.7.0", "2.6.0": "2.6.0", "": "",
	} {
		if got := upstreamVersion(in); got != want {
			t.Errorf("%q → %q, ждали %q", in, got, want)
		}
	}
}

func TestKernelAndSystemFactsHaveTexts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probes := hostProbeSet()
	for _, d := range newDrivers() {
		if o, ok := d.(hostProbeOwner); ok {
			probes = append(probes, o.hostProbes()...)
		}
	}
	seen := 0
	for _, p := range probes {
		id := p.ids[0]
		if !strings.HasPrefix(id, "kernel.") && id != "netplan.try" && id != "os.codename" {
			continue
		}
		for _, f := range p.run(ctx) {
			seen++
			if f.Title == "" || f.Missing == "" {
				t.Errorf("у факта %s нет текста", f.ID)
			}
		}
	}
	if seen < 5 {
		t.Fatalf("проверено фактов %d — набор проб неполон", seen)
	}
}

func TestPPPProbeReadsBinaryHeader(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/pppd"); err != nil {
		t.Skip("pppd не установлен")
	}
	if got := pppdNotifies("/usr/sbin/pppd"); got != hostcaps.Yes {
		t.Fatalf("pppd этой машины: %s", got)
	}
	if got := pppdNotifies("/bin/sh"); got != hostcaps.No {
		t.Fatalf("оболочка без libsystemd: %s", got)
	}
	if got := pppdNotifies(filepath.Join(t.TempDir(), "нет")); got != hostcaps.Unknown {
		t.Fatalf("без файла: %s", got)
	}
	facts := probePPP(context.Background())
	if len(facts) != 2 || facts[0].ID != factPPPNotify || facts[1].ID != factPPPPlugin {
		t.Fatalf("факты пробы: %+v", facts)
	}
	for _, f := range facts {
		if f.Class != hostcaps.ClassGuard || len(f.Consumers) != 1 || f.Consumers[0] != consumerPPPoE || f.Missing == "" {
			t.Errorf("факт %s: %+v", f.ID, f)
		}
	}
}
