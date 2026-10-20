package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPPPoEUserValidation(t *testing.T) {
	for _, ok := range []string{"user@isp", "ivan.petrov", "u_1+2", "ABC-99"} {
		if !validPPPoEUser(ok) {
			t.Fatalf("логин %q должен приниматься", ok)
		}
	}
	for _, bad := range []string{"", "a\"b", "a b", "a\nb", "a\\b", strings.Repeat("x", 129)} {
		if validPPPoEUser(bad) {
			t.Fatalf("логин %q должен отвергаться", bad)
		}
	}

	if !validPPPoESecret("p@ss w0rd!") || validPPPoESecret("a\"b") || validPPPoESecret("a\nb") || validPPPoESecret("") {
		t.Fatal("проверка пароля неверна")
	}
}

func TestPPPoEPeerRejectsBadUser(t *testing.T) {
	if _, err := writePPPoEPeer("ens3", "bad user"); err == nil {
		t.Fatal("плохой логин обязан дать ошибку до записи файла")
	}
}

func TestPPPoEHookMatchesPeerLabel(t *testing.T) {
	peer := pppoePeerContent("ens3", "user@isp")
	if !strings.Contains(peer, "ipparam "+pppoePeerName+"\n") {
		t.Fatalf("в peer-файле нет метки ipparam %q:\n%s", pppoePeerName, peer)
	}
	hook, err := os.ReadFile("../../debian/assets/ppp-ip-up-vpn-panel")
	if err != nil {
		t.Fatalf("хук ip-up не найден — он обязан ехать в пакете: %v", err)
	}
	if !strings.Contains(string(hook), "\"$PPP_IPPARAM\" = \""+pppoePeerName+"\"") {
		t.Fatalf("хук сверяет не ту метку: ожидалась %q", pppoePeerName)
	}
	if !strings.Contains(string(hook), "vpn-agent wan-up") {
		t.Fatal("хук обязан звать подкоманду wan-up нашего же бинаря")
	}
}

func TestPPPoEPeerNameIsSystemdSafe(t *testing.T) {
	if strings.ContainsAny(pppoePeerName, "-/") {
		t.Fatalf("имя пира %q содержит разделитель: systemd раскроет его в путь", pppoePeerName)
	}
	if pppoeUnit != "vpn-panel-ppp@"+pppoePeerName+".service" || pppoeLegacyUnit != "ppp@"+pppoePeerName+".service" {
		t.Fatalf("имя юнита разошлось с именем пира: %q / %q", pppoeUnit, pppoeLegacyUnit)
	}
}

func TestPPPoEUnitTemplate(t *testing.T) {
	unit := readRepo(t, "debian/assets/vpn-panel-ppp@.service")
	for _, want := range []string{"Type=notify", "up_sdnotify", "call %I", "StartLimitIntervalSec=0", "Restart=on-failure",
		"ExecStartPre=/usr/libexec/vpn-panel/ppp-wait-link %I", "SuccessExitStatus=0 5 12 13 14", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("в юните нет %q", want)
		}
	}
	for _, bad := range []string{"RestartSteps", "RestartMaxDelaySec"} {
		if strings.Contains(unit, bad) {
			t.Errorf("юнит полагается на %s: systemd 249 его не знает", bad)
		}
	}
	rules := readRepo(t, "debian/rules.d/provider.mk")
	if !strings.Contains(rules, "usr/lib/systemd/system/vpn-panel-ppp@.service") || strings.Contains(rules, "ppp@vpn_panel_wan.service.d") {
		t.Fatal("пакет кладёт не тот юнит")
	}
	if hook := readRepo(t, "debian/assets/ppp-ip-up-vpn-panel"); !strings.Contains(hook, "ppp-fails-$PPP_IPPARAM") {
		t.Fatal("хук ip-up не сбрасывает счёт неудач")
	}
	if !strings.HasPrefix(pppoeFailFile, "/run/vpn-panel/ppp-fails-") {
		t.Fatalf("файл счёта не там, где его ждёт сценарий: %s", pppoeFailFile)
	}
}

func TestPPPWaitLinkBackoff(t *testing.T) {
	script := filepath.Join("..", "..", "debian", "assets", "vpn-panel-ppp-wait-link")
	run := t.TempDir()
	delays := func() string {
		cmd := exec.Command("sh", script, "vpn_panel_wan") //nolint:gosec
		cmd.Env = append(os.Environ(), "VPN_PANEL_RUN="+run, "VPN_PANEL_SLEEP=echo", "VPN_PANEL_WAIT_LINK=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("сценарий: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	var got []string
	for i := 0; i < 9; i++ {
		got = append(got, delays())
	}
	want := []string{"", "10", "20", "40", "80", "160", "320", "600", "600"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("паузы %v, ждали %v", got, want)
	}
	if err := os.Remove(filepath.Join(run, "ppp-fails-vpn_panel_wan")); err != nil {
		t.Fatal(err)
	}
	if d := delays(); d != "" {
		t.Fatalf("после сброса счёта пауза %q", d)
	}
	bad := exec.Command("sh", script, "../etc") //nolint:gosec
	bad.Env = append(os.Environ(), "VPN_PANEL_RUN="+run)
	if err := bad.Run(); err == nil {
		t.Fatal("имя пира с разделителем принято")
	}
}

func TestReplaceSecretLineKeepsOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chap-secrets")
	if err := os.WriteFile(path, []byte("\"other\" * \"x\" *\n\"labtest\" * \"old\" *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceSecretLine(path, "labtest", "\"labtest\" * \"new\" *"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path) //nolint:gosec
	txt := string(data)
	if !strings.Contains(txt, "\"other\" * \"x\" *") {
		t.Fatalf("чужая запись потеряна:\n%s", txt)
	}
	if strings.Count(txt, "labtest") != 1 {
		t.Fatalf("должна остаться одна запись логина:\n%s", txt)
	}
	if !strings.Contains(txt, "\"new\"") || strings.Contains(txt, "\"old\"") {
		t.Fatalf("пароль не заменён:\n%s", txt)
	}
}
