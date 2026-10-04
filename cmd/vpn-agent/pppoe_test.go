package main

import (
	"os"
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
	if pppoeUnit != "ppp@"+pppoePeerName+".service" {
		t.Fatalf("имя юнита разошлось с именем пира: %q", pppoeUnit)
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
