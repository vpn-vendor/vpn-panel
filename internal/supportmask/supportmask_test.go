package supportmask

import (
	"strings"
	"testing"
)

func masker() *Masker {
	m := New([]byte("ключ шлюза для теста"))
	m.Known("Комп Ирины", "AA:BB:CC:11:22:33")
	m.Known("Комп Ирины 2", "aa:bb:cc:11:22:44")
	m.Known("DESKTOP-IRINA", "aa-bb-cc-11-22-33")
	m.Known("принтер у входа", "")
	m.Alias("moy-postavshik", m.Profile("moy-postavshik"))
	return m
}

func TestBaitsNeverSurvive(t *testing.T) {
	m := masker()
	baits := map[string]string{
		"MAC":                "DHCPACK to aa:bb:cc:11:22:33 via ens4",
		"MAC через дефис":    "сосед AA-BB-CC-11-22-33 отвечает",
		"подпись устройства": "устройство «Комп Ирины» шлёт много запросов",
		"подпись другим регистром": "КОМП ИРИНЫ не отвечает",
		"сетевое имя":              "lease for desktop-irina renewed",
		"имя без MAC":              "замятие: Принтер у входа",
		"название подключения":     "profile moy-postavshik is active",
		"внешний адрес":            "peer 203.0.113.77:51820 handshake",
		"внешний адрес IPv6":       "route to 2001:db8:85a3::8a2e:370:7334 added",
		"ключ":                     "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"идентификатор машины":     "machine-id 423367654e034fe1ac0540a5b2607ae3",
		"начало ключа":             "-----BEGIN PRI" + "VATE KEY-----",
	}
	secrets := []string{"aa:bb:cc:11:22:33", "AA-BB-CC-11-22-33", "Ирин", "ИРИН", "irina", "ринтер", "postavshik",
		"113.77", "85a3", "370:7334", "xTIBA5rb", "423367654e03", "PRI" + "VATE KEY"}
	for name, line := range baits {
		out := m.Line(line)
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s: примета %q дошла до файла: %q", name, s, out)
			}
		}
		if out == line {
			t.Errorf("%s: строка не изменилась: %q", name, out)
		}
	}
}

func TestUsefulFactsStay(t *testing.T) {
	m := masker()
	keep := []string{
		"192.168.11.1 dev ens4 lladdr",
		"10.77.77.1 через канал",
		"172.16.5.4 и 127.0.0.1 и 169.254.1.1 и 100.64.3.2",
		"окт 03 17:53:58 lab vpn-agent[3590]: firewall: ruleset restored",
		"fe80::1 link-local и ff02::1 групповой",
		"224.0.0.251 групповой, 255.255.255.255 всем, 0.0.0.0 любой",
		"версия 0.3.0, ядро 7.0.0-38, потери 0.25 %",
	}
	for _, line := range keep {
		if out := m.Line(line); out != line {
			t.Errorf("полезное изменено: %q → %q", line, out)
		}
	}
	out := m.Line("peer 203.0.113.77 handshake")
	if !strings.Contains(out, "203.0.x.x~") {
		t.Errorf("страна и оператор внешнего адреса потеряны: %q", out)
	}
}

func TestNamesAreStableAndLinked(t *testing.T) {
	a, b := masker(), masker()
	if a.Device("aa:bb:cc:11:22:33") != b.Device("AA-BB-CC-11-22-33") {
		t.Fatal("имя устройства не постоянно")
	}
	other := New([]byte("другой шлюз"))
	if a.Device("aa:bb:cc:11:22:33") == other.Device("aa:bb:cc:11:22:33") {
		t.Fatal("имена совпали на разных шлюзах")
	}
	dev := a.Device("aa:bb:cc:11:22:33")
	for _, line := range []string{"Комп Ирины", "desktop-irina", "aa:bb:cc:11:22:33"} {
		if got := a.Line(line); got != dev {
			t.Errorf("%q → %q, ожидалось одно имя %q", line, got, dev)
		}
	}
	if got := a.Line("Комп Ирины 2"); got != a.Device("aa:bb:cc:11:22:44") {
		t.Errorf("длинная подпись порвана короткой: %q", got)
	}
	x, y := a.Line("к 203.0.113.77"), a.Line("к 203.0.113.78")
	if x == y {
		t.Error("разные внешние адреса неразличимы")
	}
	if a.Line("к 203.0.113.77") != x {
		t.Error("метка адреса не постоянна")
	}
}

func TestShortNamesAreNotReplaced(t *testing.T) {
	m := New([]byte("k"))
	m.Known("ПК", "aa:bb:cc:00:00:01")
	if got := m.Line("ПК включён, ПКМ нажата"); got != "ПК включён, ПКМ нажата" {
		t.Errorf("короткое имя заменено: %q", got)
	}
}

func FuzzLine(f *testing.F) {
	f.Add("aa:bb:cc:11:22:33 203.0.113.77 Комп Ирины")
	f.Add("::ffff:203.0.113.77 1:2:3:4:5:6:7:8 17:53:58")
	f.Fuzz(func(t *testing.T, s string) {
		m := masker()
		out := m.Line(s)
		if strings.Contains(strings.ToLower(out), "aa:bb:cc:11:22:33") || strings.Contains(out, "203.0.113.77") {
			t.Fatalf("примета дошла до файла: %q → %q", s, out)
		}
	})
}
