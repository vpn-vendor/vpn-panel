package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/console"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

type fakeProbe struct{ obs []observation }

func testSurroundings(p *fakeProbe) *surroundings {
	s := newSurroundings(func() bool { return false })
	s.probes = []surroundProbe{{ids: []string{"x"}, run: func(context.Context, surroundEnv) []observation { return p.obs }}}
	s.queryUnits = func() (map[string]svcState, bool) { return map[string]svcState{}, true }
	s.now = func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }
	return s
}

func observed(id string, a hostcaps.Answer) hostcaps.Fact {
	return hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: a, How: hostcaps.HowFile}
}

func TestFactNeedsTwoEqualObservations(t *testing.T) {
	p := &fakeProbe{obs: seen(observed("x", hostcaps.No))}
	s := testSurroundings(p)
	if !s.step() {
		t.Fatal("первое наблюдение ещё не подтверждено")
	}
	if st := s.snap.Load(); !st.Settling || len(st.Facts) != 0 {
		t.Fatalf("после первого наблюдения факта ещё нет: %+v", st)
	}
	if s.step() {
		t.Fatal("второе одинаковое наблюдение подтверждает факт")
	}
	if st := s.snap.Load(); st.Settling || len(st.Facts) != 1 || st.Facts[0].Answer != hostcaps.No {
		t.Fatalf("два одинаковых наблюдения публикуют факт: %+v", st)
	}
	p.obs = seen(observed("x", hostcaps.Yes))
	s.step()
	if st := s.snap.Load(); st.Facts[0].Answer != hostcaps.No {
		t.Fatal("одиночное наблюдение перекрасило факт")
	}
	s.step()
	if st := s.snap.Load(); st.Facts[0].Answer != hostcaps.Yes {
		t.Fatal("второе одинаковое наблюдение не перекрасило факт")
	}
}

func TestMovingIsBounded(t *testing.T) {
	p := &fakeProbe{obs: []observation{{Fact: observed("x", hostcaps.Yes), moving: true}}}
	s := testSurroundings(p)
	for i := 0; i < settleSkipsMax; i++ {
		s.step()
	}
	if len(s.snap.Load().Facts) != 0 {
		t.Fatal("в переходе наблюдения не засчитываются")
	}
	s.step()
	s.step()
	if st := s.snap.Load(); len(st.Facts) != 1 || st.Facts[0].Answer != hostcaps.Yes {
		t.Fatalf("после двух тактов перехода факт обязан появиться: %+v", st)
	}

	p.obs = []observation{{Fact: observed("x", hostcaps.Unknown), moving: true}}
	for i := 0; i < 2*settleSkipsMax+2; i++ {
		s.step()
	}
	if st := s.snap.Load(); st.Facts[0].Answer != hostcaps.Yes {
		t.Fatalf("переход стёр найденное: %+v", st.Facts[0])
	}
}

func TestHoldKeepsPublished(t *testing.T) {
	p := &fakeProbe{obs: seen(observed("x", hostcaps.Yes))}
	s := testSurroundings(p)
	s.step()
	s.step()
	p.obs = []observation{{Fact: observed("x", hostcaps.Unknown), hold: true}}
	for i := 0; i < 5; i++ {
		s.step()
	}
	if st := s.snap.Load(); st.Facts[0].Answer != hostcaps.Yes {
		t.Fatalf("окно сети стёрло найденное: %+v", st.Facts[0])
	}
}

func TestParseSvcStates(t *testing.T) {
	out := "Id=isc-dhcp-server.service\nUnitFileState=enabled\nActiveState=activating\nSubState=auto-restart\n\n" +
		"Id=kea-dhcp4-server.service\nUnitFileState=enabled\nActiveState=activating\nSubState=start\n\n" +
		"Id=shellinabox.service\nUnitFileState=generated\nActiveState=active\nSubState=running\n"
	got := parseSvcStates(out)
	if st := got["isc-dhcp-server"]; !st.Enabled || st.Active || st.Moving {
		t.Fatalf("auto-restart — не переход, служба не работает: %+v", st)
	}
	if st := got["kea-dhcp4-server"]; !st.Moving {
		t.Fatalf("start — переход: %+v", st)
	}
	if st := got["shellinabox"]; !st.Enabled || !st.Active {
		t.Fatalf("служба из старого init-сценария считается включённой: %+v", st)
	}
}

func writeFixture(t *testing.T, root, path, body string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

func linkFixture(t *testing.T, root, path, target string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func TestPanelPorts(t *testing.T) {
	root := t.TempDir()
	if h, s := panelPorts(root); h != 80 || s != 443 {
		t.Fatalf("без файла — порты по умолчанию: %d %d", h, s)
	}
	writeFixture(t, root, panelEnv, "APP_PORT=\nAPP_TLS_PORT=\"8443\"\n")
	if h, s := panelPorts(root); h != 80 || s != 8443 {
		t.Fatalf("пустой порт — по умолчанию, значение в кавычках читается: %d %d", h, s)
	}
}

func TestDHCPConfigCards(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/default/isc-dhcp-server", "INTERFACESv4=\"ens3\"\nINTERFACESv6=\"\"\n")
	if got, files := dhcpConfigCards(root, "isc-dhcp-server"); len(got) != 1 || got[0] != "ens3" || files[0] != "/etc/default/isc-dhcp-server" {
		t.Fatalf("карта и файл конфига старого dhcpd: %v %v", got, files)
	}
	writeFixture(t, root, "etc/dnsmasq.conf", "no-resolv\n")
	if got, _ := dhcpConfigCards(root, "dnsmasq"); got != nil {
		t.Fatalf("dnsmasq без раздачи — не сервер DHCP: %v", got)
	}
	writeFixture(t, root, "etc/dnsmasq.d/lan.conf", "dhcp-range=10.0.0.10,10.0.0.99\n")
	if got, files := dhcpConfigCards(root, "dnsmasq"); len(got) != 1 || got[0] != "*" || files[0] != "/etc/dnsmasq.d/lan.conf" {
		t.Fatalf("dnsmasq без interface= раздаёт на всех картах: %v %v", got, files)
	}
}

const (
	udpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

	dhcpdLine = "  12: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 21311 2 0000000000000000 0"
)

func procFixture(t *testing.T, root, table, line, cgroup, comm string) {
	t.Helper()
	header := udpHeader
	if table == "tcp" {
		header = tcpHeader
	}
	writeFixture(t, root, "proc/net/"+table, header+line+"\n")
	inode := strings.Fields(line)[9]
	linkFixture(t, root, "proc/629/fd/9", "socket:["+inode+"]")
	writeFixture(t, root, "proc/629/cgroup", cgroup+"\n")
	writeFixture(t, root, "proc/629/comm", comm+"\n")
}

func stubEnv(root string, units map[string]svcState, known bool) surroundEnv {
	return surroundEnv{root: root, units: func(u string) svcState { return units[u] }, unitsKnown: known,
		awaiting: func() bool { return false }}
}

func noCard(netip.Addr) string { return "" }

func TestForeignDHCPOnStand(t *testing.T) {
	root := t.TempDir()
	procFixture(t, root, "udp", dhcpdLine, "0::/system.slice/isc-dhcp-server.service", "dhcpd")
	writeFixture(t, root, "etc/default/isc-dhcp-server", "INTERFACESv4=\"ens3\"\n")
	r, ok := scanForeignDHCP(stubEnv(root, nil, true), noCard)
	if !ok || !r.Found || len(r.Cards) != 1 || r.Cards[0] != "ens3" || r.Name != "ISC DHCP" {
		t.Fatalf("чужой dhcpd на ens3: %+v", r)
	}
	if !r.touches([]string{"ens3"}) || r.touches([]string{"ens4"}) {
		t.Fatal("касается только своей карты")
	}
	if !strings.Contains(strings.Join(r.Support, ";"), "/etc/default/isc-dhcp-server") {
		t.Fatalf("в сведениях поддержки нет файла конфига: %v", r.Support)
	}
}

func TestOwnKeaIsNotForeign(t *testing.T) {
	root := t.TempDir()
	procFixture(t, root, "udp", strings.Replace(dhcpdLine, "00000000:0043", "010BA8C0:0043", 1),
		"0::/system.slice/kea-dhcp4-server.service", "kea-dhcp4")
	r, _ := scanForeignDHCP(stubEnv(root, nil, true), func(netip.Addr) string { return "ens3" })
	if r.Found || !r.ownServes([]string{"ens3"}) {
		t.Fatalf("наша Kea с сокетом на ens3 — своя раздача работает: %+v", r)
	}
}

func TestOwnerlessSocketDoesNotLock(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "proc/net/udp", udpHeader+dhcpdLine+"\n")
	r, ok := scanForeignDHCP(stubEnv(root, nil, true), noCard)
	if !ok || !r.Found || len(r.Cards) != 0 || r.touches([]string{"ens3"}) {
		t.Fatalf("без владельца — сведение без замка: %+v", r)
	}
}

func TestEnabledServiceCountsWithoutSocket(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "proc/net/udp", udpHeader)
	writeFixture(t, root, "etc/default/isc-dhcp-server", "INTERFACESv4=\"ens3\"\n")
	units := map[string]svcState{"isc-dhcp-server": {Enabled: true}}
	r, _ := scanForeignDHCP(stubEnv(root, units, true), noCard)
	if !r.Found || !r.touches([]string{"ens3"}) {
		t.Fatalf("включённая служба на ens3: %+v", r)
	}

	r, _ = scanForeignDHCP(stubEnv(root, nil, false), noCard)
	if r.Found || !r.UnitsUnknown {
		t.Fatalf("без systemd: %+v", r)
	}
	obs := probeDHCPHost(context.Background(), stubEnv(root, nil, false))
	if obs[0].Answer != hostcaps.Unknown {
		t.Fatalf("без systemd и без сокета — «не удалось проверить»: %+v", obs[0].Fact)
	}
}

func TestPortOwnerBlocks(t *testing.T) {

	wan := "   1: 057100CB:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1"
	root := t.TempDir()
	procFixture(t, root, "tcp", wan, "0::/system.slice/openvpn-server@a.service", "openvpn")
	if h := portOwner(root, 443, blocksPanel); h.Found || !h.OK {
		t.Fatalf("сервер на адресе WAN панели не мешает: %+v", h)
	}
	all := "   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1"
	root = t.TempDir()
	procFixture(t, root, "tcp", all, "0::/system.slice/apache2.service", "apache2")
	if h := portOwner(root, 443, blocksLocal); !h.Found || h.Name != "Apache" {
		t.Fatalf("Apache на всех адресах держит порт панели: %+v", h)
	}
	root = t.TempDir()
	procFixture(t, root, "tcp", all, "0::/system.slice/vpn-panel.service", "vpn-panel")
	if h := portOwner(root, 443, blocksLocal); h.Found {
		t.Fatalf("своя служба панели — не чужая: %+v", h)
	}
}

func TestConsolePortTaken(t *testing.T) {
	f := healthy()
	f.PanelAnswers, f.PanelPortTaken = false, "Apache"
	st := gatewayStatus(f, numRestart)
	if st.Level != console.Bad || st.Suggest == numRestart {
		t.Fatalf("порт занят — перезапуск не предлагается: %+v", st)
	}
	advice := strings.Join(st.Advice, " ")
	if !strings.Contains(advice, "Apache") || !strings.Contains(advice, "не поможет") {
		t.Fatalf("совет: %q", advice)
	}
}

func TestPortTakenIsExternal(t *testing.T) {
	f := healthFacts{PanelKnown: true, Panel: unitState{Active: "active"}, PortTaken: true}
	for _, p := range healthProbes {
		bad := p.bad(f, noRestartBase)
		switch p.name {
		case "panel-unserved":
			if bad {
				t.Error("при чужом порте panel-unserved не засчитывается")
			}
		case "panel-port-taken":
			if !bad {
				t.Error("panel-port-taken не сработал")
			}
		}
	}
}

func TestForwardBootFiles(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/sysctl.conf", "# net.ipv4.ip_forward=1\nnet.ipv4.ip_forward=1\n")

	linkFixture(t, root, "etc/sysctl.d/99-sysctl.conf", "../sysctl.conf")
	if got := forwardBootFiles(root); len(got) != 1 {
		t.Fatalf("одна настройка — одна строка: %v", got)
	}

	root = t.TempDir()
	writeFixture(t, root, "etc/sysctl.d/60-router.conf", "net/ipv4/conf/all/forwarding = 1\n")
	if got := forwardBootFiles(root); len(got) != 1 {
		t.Fatalf("forwarding карты — та же пересылка: %v", got)
	}

	writeFixture(t, root, "etc/sysctl.d/90-off.conf", "net.ipv4.ip_forward = 0\n")
	if got := forwardBootFiles(root); len(got) != 0 {
		t.Fatalf("поздний файл выключил пересылку: %v", got)
	}

	root = t.TempDir()
	writeFixture(t, root, "usr/lib/sysctl.d/50-x.conf", "net.ipv4.ip_forward=1\n")
	writeFixture(t, root, "etc/sysctl.d/50-x.conf", "net.ipv4.ip_forward=0\n")
	if got := forwardBootFiles(root); len(got) != 0 {
		t.Fatalf("файл в /etc заменяет одноимённый: %v", got)
	}
}

func TestExposedKeyFiles(t *testing.T) {
	old := keyOwner
	keyOwner = uint32(os.Getuid()) //nolint:gosec
	defer func() { keyOwner = old }()
	root := t.TempDir()
	writeFixture(t, root, filepath.Join(ovpnDir, ovpnProfilePfx+"a.conf"), "ключ")

	if err := os.Chmod(filepath.Join(root, ovpnDir), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if got := exposedKeyFiles(root); len(got) != 0 {
		t.Fatalf("закрытый файл в открытом каталоге — это не утечка: %v", got)
	}
	if err := os.Chmod(filepath.Join(root, ovpnDir, ovpnProfilePfx+"a.conf"), 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if got := exposedKeyFiles(root); len(got) != 1 {
		t.Fatal("файл ключа, открытый всем, не замечен")
	}
}
