package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readRepo(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", rel)) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFirewallUnitRunsBeforeNetwork(t *testing.T) {
	unit := readRepo(t, "debian/vpn-panel.vpn-panel-firewall.service")
	for _, want := range []string{
		"Type=oneshot", "RemainAfterExit=yes", "DefaultDependencies=no",
		"Wants=network-pre.target", "ExecStart=/usr/libexec/vpn-panel/firewall-boot",
	} {
		if !strings.Contains(unit, "\n"+want+"\n") {
			t.Errorf("юнит защиты: нет строки %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^Before=.*\bnetwork-pre\.target\b`).MatchString(unit) {
		t.Error("юнит защиты обязан стоять Before=network-pre.target")
	}
	rules := readRepo(t, "debian/rules") + readRepo(t, "debian/rules.d/boot-guard.mk") + readRepo(t, "debian/rules.d/provider.mk")
	for _, want := range []string{"usr/libexec/vpn-panel/firewall-boot", "usr/share/vpn-panel/lockdown.nft",
		"usr/libexec/vpn-panel/ppp-wait-link", "dh_installsystemd --name=vpn-panel-firewall"} {
		if !strings.Contains(rules, want) {
			t.Errorf("сборка пакета не устанавливает %q", want)
		}
	}
}

func TestForwardingOnlyAfterRules(t *testing.T) {
	if strings.Contains(sysctlContent, "ip_forward") {
		t.Fatal("файл sysctl включает пересылку на ранней стадии загрузки — до правил")
	}
	script := readRepo(t, "debian/assets/vpn-panel-firewall-boot")
	load := strings.Index(script, `if "$NFT" -f "$RULES"; then`)
	on := strings.Index(script, "echo 1 > /proc/sys/net/ipv4/ip_forward")
	if load < 0 || on < 0 || on < load {
		t.Fatal("сценарий обязан включать пересылку только внутри ветки успешной загрузки правил")
	}
	if !strings.Contains(script, "echo 0 > /proc/sys/net/ipv4/ip_forward") {
		t.Fatal("при неудаче — выключенная пересылка (fail-closed)")
	}

	last := strings.Index(script, `"$NFT" -f "$LOCKDOWN_LAST"`)
	static := strings.Index(script, `"$NFT" -f "$LOCKDOWN_STATIC"`)
	if last < 0 || static < 0 || static < last {
		t.Fatal("аварийный запрет: набор по последней конфигурации, без него — статичный")
	}
	if !strings.Contains(script, "LOCKDOWN_LAST="+lockdownFile) {
		t.Fatalf("сценарий загрузки ищет набор по последней конфигурации не там, куда его пишет агент (%s)", lockdownFile)
	}
	if out, err := exec.Command("sh", "-n", filepath.Join("..", "..", "debian/assets/vpn-panel-firewall-boot")).CombinedOutput(); err != nil { //nolint:gosec
		t.Fatalf("сценарий не разбирается оболочкой: %s", out)
	}
}

func TestPPPWaitFindsLinkInPeer(t *testing.T) {
	script := readRepo(t, "debian/assets/vpn-panel-ppp-wait-link")
	if !strings.Contains(script, `s/^plugin pppoe\.so nic-\(.*\)$/\1/p`) {
		t.Fatal("сценарий ожидания ищет имя карты не по форме, которую пишет агент")
	}
	re := regexp.MustCompile(`(?m)^plugin pppoe\.so nic-(.*)$`)
	for _, nic := range []string{"ens3", "ens3.100", "enp1s0f0.2"} {
		m := re.FindStringSubmatch(pppoePeerContent(nic, "user"))
		if m == nil || m[1] != nic {
			t.Errorf("из пира карты %q сценарий извлечёт %v", nic, m)
		}
	}
	dropin := readRepo(t, "debian/assets/ppp-vpn-panel.conf")
	if !strings.Contains(dropin, "\nExecStartPre=/usr/libexec/vpn-panel/ppp-wait-link\n") {
		t.Fatal("вставка ppp@ не ждёт карту перед pppd")
	}
	if out, err := exec.Command("sh", "-n", filepath.Join("..", "..", "debian/assets/vpn-panel-ppp-wait-link")).CombinedOutput(); err != nil { //nolint:gosec
		t.Fatalf("сценарий ожидания не разбирается оболочкой: %s", out)
	}
}

func TestStaticLockdownHasNoMulticastOut(t *testing.T) {
	nft := readRepo(t, "debian/assets/vpn-panel-lockdown.nft")
	for _, bad := range []string{"224.0.0.0", "255.255.255.255", "ff00::"} {
		if strings.Contains(nft, bad) {
			t.Errorf("статичный аварийный набор разрешает %s", bad)
		}
	}
	for _, want := range []string{"udp sport 68 udp dport 67 accept", "udp sport 67 udp dport 68 accept"} {
		if strings.Count(nft, want) != 2 {
			t.Errorf("DHCP клиента и сервера — явными портами в обе стороны: %q", want)
		}
	}
}

func TestPurgeRemovesLockdown(t *testing.T) {
	if !strings.Contains(readRepo(t, "debian/postrm"), "rm -f "+lockdownFile+"\n") {
		t.Fatal("postrm purge не удаляет аварийный набор по последней конфигурации")
	}
}
