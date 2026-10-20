package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
)

func TestEveryOpKindHasHandler(t *testing.T) {
	for _, k := range takeover.Kinds() {
		if _, ok := opHandlers[k]; !ok {
			t.Errorf("у вида %q нет исполнителя", k)
		}
	}
	for k := range opHandlers {
		if !slices.Contains(takeover.Kinds(), k) {
			t.Errorf("исполнитель %q без вида в модели", k)
		}
	}
	_, r := tkStand(t)
	if err := r.do(&takeover.Journal{}, takeover.PendingOp{Op: takeover.Op{Kind: "нет такого"}}); err == nil {
		t.Fatal("незнакомый вид исполнен")
	}
}

func TestTakeoverConsentResolve(t *testing.T) {
	f, r := tkStand(t)
	plan := tkPlan(t, r)
	lans, cards := []string{"ens3"}, []string{"ens2", "ens3"}

	if sel, rerr := (*takeoverConsent)(nil).resolve(r, lans, cards); rerr != nil || len(sel.Items) != 0 {
		t.Fatalf("без согласия: %+v %v", sel, rerr)
	}
	if sel, rerr := (&takeoverConsent{Digest: plan.Digest}).resolve(r, lans, cards); rerr != nil || len(sel.Items) != 0 {
		t.Fatalf("согласие без пунктов: %+v %v", sel, rerr)
	}
	ok := &takeoverConsent{IDs: []string{"legacy.dhcp", "legacy.pppoe"}, Digest: plan.Digest}
	sel, rerr := ok.resolve(r, lans, cards)
	if rerr != nil || len(sel.Items) != 2 {
		t.Fatalf("согласие на два пункта: %+v %v", sel, rerr)
	}
	if d := sel.Doomed(); !slices.Equal(d, []string{"cron", "isc-dhcp-server"}) {
		t.Fatalf("обречённые службы: %v", d)
	}
	for name, c := range map[string]*takeoverConsent{
		"чужой отпечаток":    {IDs: []string{"legacy.dhcp"}, Digest: "x"},
		"неизвестный пункт":  {IDs: []string{"нет.такого"}, Digest: plan.Digest},
		"сборка без захвата": ok,
	} {
		var rerr *agentrpc.ErrorObject
		if name == "сборка без захвата" {
			_, rerr = c.resolve(nil, lans, cards)
		} else {
			_, rerr = c.resolve(r, lans, cards)
		}
		if rerr == nil || rerr.Code != codeNetTakeover {
			t.Errorf("%s: ждали 1009, получили %+v", name, rerr)
		}
	}

	if err := os.Remove(filepath.Join(f.root, legacyvpn.BotSudoers)); err != nil {
		t.Fatal(err)
	}
	if _, rerr := ok.resolve(r, lans, cards); rerr == nil || rerr.Code != codeNetTakeover {
		t.Fatalf("изменившаяся обстановка: %+v", rerr)
	}
}

func TestTakeoverBeginAfterPreviousRun(t *testing.T) {
	f, r := tkStand(t)
	plan := tkPlan(t, r)
	if _, err := r.begin(plan); err != nil {
		t.Fatal(err)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	f.fail = "systemctl mask shellinabox.service"
	if done, _ := r.finish(); done {
		t.Fatal("проход с отказом полный")
	}

	_, err := r.begin(plan)
	if err == nil || takeoverBusyErr(err).Code != codeNetTakeBusy || !strings.Contains(takeoverBusyErr(err).Message, "подождите") {
		t.Fatalf("при незаконченном захвате: %v", err)
	}
	f.fail = ""
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("доделка: %v %v", done, err)
	}

	if _, err := r.begin(plan); err != nil {
		t.Fatalf("после done: %v", err)
	}
	if st := r.status(); st.State != "window" {
		t.Fatalf("новый захват: %+v", st)
	}

	if e := takeoverBusyErr(errTakeoverBusy); e.Code != codeNetTakeBusy || e.Data["recoverable"] != true {
		t.Fatalf("ошибка занятости: %+v", e)
	}
}

func TestTakeoverWaitDHCPRetired(t *testing.T) {
	f, r := tkStand(t)
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}

	start := f.clock
	r.waitDHCPRetired()
	if f.clock != start {
		t.Fatal("ожидание в окне")
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}

	r.waitDHCPRetired()
	if waited := f.clock.Sub(start); waited < confirmBudget || waited > 2*confirmBudget {
		t.Fatalf("ждали %v, бюджет %v", waited, confirmBudget)
	}
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("шаг 3: %v %v", done, err)
	}
	start = f.clock
	r.waitDHCPRetired()
	if f.clock != start {
		t.Fatal("ожидание после выключенной раздачи")
	}

	_, r2 := tkStand(t)
	r2.waitDHCPRetired()
}

func TestTakeoverDoomedAndResidue(t *testing.T) {
	f, r := tkStand(t)
	if r.doomed() != nil || r.residue() != nil {
		t.Fatal("без журнала есть обречённые или остатки")
	}
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	if d := r.doomed(); !slices.Contains(d, "isc-dhcp-server") || slices.ContainsFunc(d, func(s string) bool { return strings.HasSuffix(s, ".service") }) {
		t.Fatalf("обречённые: %v", d)
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("шаг 3: %v %v", done, err)
	}
	if res := r.residue(); !slices.Equal(res, []string{"resolved_header"}) {
		t.Fatalf("остатки: %v", res)
	}

	if p := tkPlan(t, r); len(p.Items) != 0 {
		t.Fatalf("план после захвата: %v", tkIDs(p))
	}

	writeFixture(t, f.root, strings.TrimPrefix(legacyvpn.ScriptNetplan, "/"), "network:\n  version: 2\n")
	writeFixture(t, f.root, strings.TrimPrefix(legacyvpn.UdevRule, "/"), "RUN+=\"/usr/local/bin/mount-usb.sh\"\n")
	writeFixture(t, f.root, strings.TrimPrefix(legacyvpn.MountUSB, "/"), "#!/bin/bash\n")
	if p := tkPlan(t, r); !slices.Contains(tkIDs(p), "legacy.netplan") {
		t.Fatalf("после повторного запуска скрипта: %v", tkIDs(p))
	}
}

func TestReportWithout(t *testing.T) {
	r := legacyvpn.Report{Markers: []string{"netplan_backup", "resolved_header", "udev_rule"}, Gateway: true, Mode: "vpn",
		Danger: []legacyvpn.Danger{{ID: "sudo", Attributed: true}}}
	out := r.Without([]string{"netplan_backup", "resolved_header"})
	if out.Gateway || out.Mode != "" || out.Danger[0].Attributed || !slices.Equal(out.Markers, []string{"udev_rule"}) {
		t.Fatalf("после вычитания: %+v", out)
	}
	if r.Danger[0].Attributed != true || len(r.Markers) != 3 {
		t.Fatal("исходный отчёт изменён")
	}
	if same := r.Without(nil); !same.Gateway || same.Mode != "vpn" {
		t.Fatalf("без остатков отчёт тот же: %+v", same)
	}
	two := r.Without([]string{"resolved_header"})
	if !two.Gateway {
		t.Fatal("две приметы разных шагов остались — шлюз")
	}
}

func TestForeignDHCPSkipsDoomed(t *testing.T) {
	root := t.TempDir()
	procFixture(t, root, "udp", dhcpdLine, "0::/system.slice/isc-dhcp-server.service", "dhcpd")
	writeFixture(t, root, "etc/default/isc-dhcp-server", "INTERFACESv4=\"ens3\"\n")
	s := testSurroundings(&fakeProbe{})
	s.env.root = root
	s.queryUnits = func() (map[string]svcState, bool) {
		return map[string]svcState{"isc-dhcp-server": {Enabled: true, Active: true}}, true
	}
	if _, bad := s.dhcpConflict([]string{"ens3"}); !bad {
		t.Fatal("без обречённых замок обязан сработать")
	}
	if _, bad := s.dhcpConflict([]string{"ens3"}, "isc-dhcp-server"); bad {
		t.Fatal("обречённая из согласия служба заперла окно")
	}

	f, r := tkStand(t)
	f.root = root
	r.sys = f.sys()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/vpn-panel"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	s.useTakeover(r)
	if _, bad := s.dhcpConflict([]string{"ens3"}); !bad {
		t.Fatal("без журнала обречённых нет")
	}
	j := takeover.Journal{Plan: takeover.Plan{Digest: strings.Repeat("a", 64), Items: []takeover.Item{{ID: "legacy.dhcp", Kind: takeover.KindService,
		Step3: []takeover.Op{{Kind: takeover.OpStop, Unit: "isc-dhcp-server.service"}}}}}, Stage: takeover.StageFinishing}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	if _, bad := s.dhcpConflict([]string{"ens3"}); bad {
		t.Fatal("обречённая по журналу служба заперла окно")
	}
	if s.env.legacyGateway() {
		t.Fatal("корень без примет — не шлюз")
	}
}

func TestTakeoverPlanStatusMethod(t *testing.T) {
	_, r := tkStand(t)
	res, rerr := r.takeoverPlanStatus(json.RawMessage(`{"lans":["ens3","нет"],"plan_cards":["ens2","ens3"]}`))
	if rerr != nil {
		t.Fatal(rerr)
	}
	out := res.(map[string]any)
	if out["state"] != "none" || out["digest"] == "" || len(out["items"].([]map[string]any)) == 0 {
		t.Fatalf("ответ: %+v", out)
	}
	if _, ok := out["backup"]; ok {
		t.Fatal("каталог копии без журнала")
	}
	if _, rerr := r.takeoverPlanStatus(json.RawMessage(`{"lans":5}`)); rerr == nil {
		t.Fatal("негодные параметры приняты")
	}
	plan := tkPlan(t, r)
	if _, err := r.begin(plan); err != nil {
		t.Fatal(err)
	}
	res, rerr = r.takeoverPlanStatus(nil)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if out := res.(map[string]any); out["state"] != "window" || out["failed"] != 0 {
		t.Fatalf("в окне: %+v", out)
	}
	for i := 0; i < 10; i++ {
		if _, rerr = r.takeoverPlanStatus(nil); rerr != nil {
			break
		}
	}
	if rerr == nil || rerr.Code != codeHostBusy {
		t.Fatalf("ограничитель не сработал: %+v", rerr)
	}

	for i := 0; i < 3; i++ {
		res, rerr = r.takeoverPlanStatus(json.RawMessage(`{"state_only":true}`))
		if rerr != nil {
			t.Fatal(rerr)
		}
	}
	if out := res.(map[string]any); out["state"] != "window" || out["digest"] != nil || len(out["items"].([]map[string]any)) != 0 {
		t.Fatalf("только этап: %+v", out)
	}
}

func TestLegacyRootFollowsJournal(t *testing.T) {
	f, r := tkStand(t)
	if root, src := r.legacyRoot(); root != f.root || src != legacySourceLive {
		t.Fatalf("без журнала: %s %s", root, src)
	}
	res, _ := r.legacySettingsStatus(nil)
	if out := res.(map[string]any); out["found"] != true || out["source"] != legacySourceLive {
		t.Fatalf("настройки живой системы: %+v", out)
	}
	if _, err := r.begin(tkPlan(t, r)); err != nil {
		t.Fatal(err)
	}
	if _, src := r.legacyRoot(); src != legacySourceLive {
		t.Fatal("в окне файлы ещё на месте")
	}
	if err := r.confirm(); err != nil {
		t.Fatal(err)
	}
	if done, err := r.finish(); err != nil || !done {
		t.Fatalf("шаг 3: %v %v", done, err)
	}
	root, src := r.legacyRoot()
	if src != legacySourceBackup || root != filepath.Join(f.root, backupDir(t, r)) {
		t.Fatalf("после захвата: %s %s", root, src)
	}
	res, _ = r.legacySettingsStatus(nil)
	out := res.(map[string]any)
	if out["found"] != true || out["source"] != legacySourceBackup {
		t.Fatalf("настройки из копии: %+v", out)
	}

	data, _ := json.Marshal(out["settings"])
	var st legacyvpn.Settings
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if st.WAN.Method != legacyvpn.MethodPPPoE || st.LAN.CIDR != "192.168.11.1/24" || st.VPN == nil || st.VPN.Protocol != legacyvpn.ProtocolOpenVPN {
		t.Fatalf("настройки из копии: %+v", st)
	}
	if text, err := legacyVPNConfig(root, legacyvpn.ProtocolOpenVPN); err != nil || !strings.Contains(text, "dev tun0") {
		t.Fatalf("файл подключения из копии: %q %v", text, err)
	}
	if _, err := legacyVPNConfig(root, legacyvpn.ProtocolWireGuard); err == nil {
		t.Fatal("подключения другого протокола у старого шлюза нет")
	}
	if _, err := legacyVPNConfig(root, "x"); err == nil {
		t.Fatal("чужой протокол принят")
	}

	f2 := &tkFake{root: tkRoot(t, map[string]string{}), known: true}
	res, _ = tkRunner(f2).legacySettingsStatus(nil)
	if out := res.(map[string]any); out["found"] != false || out["settings"] != nil {
		t.Fatalf("чистая машина: %+v", out)
	}
}
