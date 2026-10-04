package ovpngen

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	caPEM   = "-----BEGIN CERTIFICATE-----\nMIIBCA\n-----END CERTIFICATE-----"
	certPEM = "-----BEGIN CERTIFICATE-----\nMIIBCE\n-----END CERTIFICATE-----"
	tcv2    = "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nAAAA\n-----END OpenVPN tls-crypt-v2 client key-----"
)

var keyPEM = testingKey("-----BEGIN TESTING KEY-----\nMIIBKE\n-----END TESTING KEY-----")

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func vendorFile() string {
	return `# конфигурация от поставщика
client
dev tun
proto udp
remote vpn.example.net 1194
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
<ca>
` + caPEM + `
</ca>
<cert>
` + certPEM + `
</cert>
<key>
` + keyPEM + `
</key>
<tls-crypt-v2>
` + tcv2 + `
</tls-crypt-v2>
`
}

func TestParseVendorFile(t *testing.T) {
	p, warnings, err := Parse(vendorFile())
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	m := p.Meta()
	if m.Protocol != ID || m.Transport != vpndriver.TransportUDP {
		t.Fatalf("паспорт профиля: %+v", m)
	}
	if m.EndpointHost != "vpn.example.net" || m.EndpointPort != 1194 || !m.FullTunnel {
		t.Fatalf("сервер: %+v", m)
	}
	for _, tag := range []string{"ca", "cert", "key", "tls-crypt-v2"} {
		if p.Inline[tag] == "" {
			t.Errorf("блок %s не разобран", tag)
		}
	}
	if !p.hasOption("remote-cert-tls") || !p.hasOption("data-ciphers") {
		t.Fatal("опции проверки сервера и шифров обязаны сохраняться")
	}

	if len(warnings) != 0 {
		t.Fatalf("файл поставщика обязан импортироваться без предупреждений: %v", warnings)
	}
	if !p.VoiceFit() || !p.Meta().VoiceFit || p.Overhead(false) != 52 || !p.KernelExpected() {
		t.Fatalf("паспорт файла поставщика: fit=%v overhead=%d kernel=%v", p.VoiceFit(), p.Overhead(false), p.KernelExpected())
	}
}

func TestQuotedValuesWithSpaces(t *testing.T) {
	src := vendorFile() + `remote-cert-eku "TLS Web Server Authentication"` + "\n" + `verify-x509-name "CN=vpn-server, O=Example" subject` + "\n"
	p, warnings, err := Parse(src)
	if err != nil {
		t.Fatalf("законные значения отклонены: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("лишние предупреждения: %v", warnings)
	}
	lib := string(p.Library())
	for _, want := range []string{`remote-cert-eku "TLS Web Server Authentication"`, `verify-x509-name "CN=vpn-server, O=Example" subject`} {
		if !strings.Contains(lib, want+"\n") {
			t.Fatalf("канонический файл потерял кавычки:\n%s", lib)
		}
	}
	if again, _, err := Parse(lib); err != nil || string(again.Library()) != lib {
		t.Fatalf("повторный разбор с кавычками: %v", err)
	}

	if _, _, err := Parse(vendorFile() + `auth "SHA 256"` + "\n"); err == nil {
		t.Fatal("пробел в значении auth обязан быть отклонён")
	}

	if _, _, err := Parse(vendorFile() + "verify-x509-name \"a\\\"b\" name\n"); err == nil {
		t.Fatal("экранированная кавычка не должна попадать в файл")
	}
}

func TestLegacySynonymsAreFixedClientSide(t *testing.T) {

	p, w, err := Parse(vendorFile() + "ncp-ciphers AES-128-GCM\n")
	if err != nil || strings.Contains(string(p.Library()), "ncp-ciphers") || !strings.Contains(strings.Join(w, " "), "ncp-ciphers") {
		t.Fatalf("синоним после настоящей записи: %v %v", err, w)
	}
	if strings.Count(string(p.Library()), "data-ciphers") != 1 {
		t.Fatalf("data-ciphers обязан остаться один:\n%s", p.Library())
	}
	src := strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n", "ncp-ciphers AES-128-GCM\ndata-ciphers AES-256-GCM\n", 1)
	p, _, err = Parse(src)
	if err != nil || !strings.Contains(string(p.Library()), "data-ciphers AES-256-GCM\n") || strings.Contains(string(p.Library()), "AES-128-GCM") {
		t.Fatalf("настоящая запись обязана победить синоним: %v\n%s", err, p.Library())
	}
	onlyAlias := strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n", "ncp-ciphers AES-256-GCM\n", 1)
	if p, _, err = Parse(onlyAlias); err != nil || !strings.Contains(string(p.Library()), "data-ciphers AES-256-GCM\n") {
		t.Fatalf("одинокий синоним обязан стать data-ciphers: %v", err)
	}

	p, w, err = Parse(vendorFile() + "tls-remote server\n")
	if err != nil || !strings.Contains(string(p.Library()), "verify-x509-name server name-prefix\n") || !strings.Contains(strings.Join(w, " "), "tls-remote") {
		t.Fatalf("tls-remote: %v %v", err, w)
	}

	p, w, err = Parse(vendorFile() + "tls-version-min 1.0\n")
	if err != nil || !strings.Contains(string(p.Library()), "tls-version-min 1.2\n") || !strings.Contains(strings.Join(w, " "), "TLS") {
		t.Fatalf("tls-version-min: %v %v", err, w)
	}
}

func TestCipherFitnessMarksAndRefuses(t *testing.T) {
	cbc := strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "data-ciphers AES-256-CBC\nauth SHA512", 1)
	p, w, err := Parse(cbc)
	if err != nil {
		t.Fatalf("CBC — не отказ: %v", err)
	}
	if p.VoiceFit() || p.Meta().VoiceFit || !p.CipherUnfit || p.KernelExpected() {
		t.Fatalf("CBC обязан получить пометку и ожидание шифрования в процессе: %+v", p)
	}
	if p.Overhead(false) != 132 {
		t.Fatalf("оверхед CBC+SHA512: %d", p.Overhead(false))
	}
	if !strings.Contains(strings.Join(w, " "), "не годится для разговоров") {
		t.Fatalf("тихое предупреждение обязано быть: %v", w)
	}
	mixed := strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "data-ciphers AES-256-GCM:AES-256-CBC", 1)
	p, w, err = Parse(mixed)
	if err != nil || !p.VoiceFit() || p.Overhead(false) != 88 || !strings.Contains(strings.Join(w, " "), "решает сервер") {
		t.Fatalf("смешанный список: %v fit=%v overhead=%d %v", err, p.VoiceFit(), p.Overhead(false), w)
	}
	for _, bad := range []string{"cipher BF-CBC", "auth MD5", "cipher none"} {
		if _, _, err := Parse(vendorFile() + bad + "\n"); err == nil || !strings.Contains(err.Error(), "небезопасный способ шифрования") {
			t.Errorf("%q: обязан быть отказ с тихим текстом, получили %v", bad, err)
		}
	}
	des := strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "data-ciphers AES-256-GCM:DES-EDE3-CBC", 1)
	if _, _, err := Parse(des); err == nil || !strings.Contains(err.Error(), "DES-EDE3-CBC") {
		t.Fatalf("снятый шифр в списке обязан быть назван в отказе: %v", err)
	}

	p, _, err = Parse(strings.Replace(vendorFile(), "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "data-ciphers FUTURE-512-XYZ", 1))
	if err != nil || p.VoiceFit() {
		t.Fatalf("незнакомый шифр: %v fit=%v", err, p.VoiceFit())
	}
}

func TestEmptyAndBinaryFilesAreNamed(t *testing.T) {
	if _, _, err := Parse("\n\n"); err == nil || !strings.Contains(err.Error(), "пуст") {
		t.Fatalf("пустой файл: %v", err)
	}
	if _, _, err := Parse("\x00\x01\x02PK\x03\x04" + strings.Repeat("\x00", 64)); err == nil || !strings.Contains(err.Error(), "не текст") {
		t.Fatalf("двоичный файл: %v", err)
	}
	if _, _, err := Parse("\xff\xfeне текст"); err == nil || !strings.Contains(err.Error(), "не текст") {
		t.Fatalf("не UTF-8: %v", err)
	}

	if msg := vpndriver.ShapeError(""); !strings.Contains(msg, "пуст") {
		t.Fatalf("форма пустого файла: %q", msg)
	}
}

func TestLibraryRoundTrip(t *testing.T) {
	p, _, err := Parse(vendorFile())
	if err != nil {
		t.Fatal(err)
	}
	lib := p.Library()
	again, warnings, err := Parse(string(lib))
	if err != nil {
		t.Fatalf("повторный разбор: %v\n%s", err, lib)
	}
	if len(warnings) != 0 {
		t.Fatalf("библиотечный файл не должен давать предупреждений: %v\n%s", warnings, lib)
	}
	if string(again.Library()) != string(lib) {
		t.Fatalf("библиотечный файл нестабилен:\n%s\n---\n%s", lib, again.Library())
	}
}

func TestGenerateStructuralGuards(t *testing.T) {
	p, _, err := Parse(vendorFile())
	if err != nil {
		t.Fatal(err)
	}
	out := string(p.Generate(Render{
		Iface: TunnelIface, Mark: vpndriver.Mark, MTU: 1448,
		Remotes: []Remote{{Host: "192.0.2.10", Port: 1194}}, Management: "/run/x/mgmt.sock",
	}))
	for _, want := range []string{
		"dev ovpn-vpn0\n", "dev-type tun\n", "remote 192.0.2.10 1194 udp\n",
		"mark 51820\n", "route-noexec\n", "route-nopull\n", "dns-updown disable\n",
		`pull-filter accept "ifconfig "`, `pull-filter reject "compress"`, `pull-filter ignore ""`,
		"tun-mtu 1448\n", "explicit-exit-notify 1\n", "management /run/x/mgmt.sock unix\n",
		"management-client-user root\n", "remote-cert-tls server\n", "<ca>\n" + caPEM + "\n</ca>\n",
		"nobind\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в действующем файле нет %q:\n%s", want, out)
		}
	}
	for _, forbidden := range []string{"\nup ", "\ndown ", "script-security", "vpn.example.net", "verb 3\nverb", "persist-tun"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("в действующем файле не должно быть %q", forbidden)
		}
	}

	accept := strings.Index(out, `pull-filter accept "`)
	reject := strings.Index(out, `pull-filter reject "`)
	catchAll := strings.Index(out, `pull-filter ignore ""`)
	if accept >= reject || reject >= catchAll {
		t.Fatal("фильтр пуша обязан идти: принять → отвергнуть → игнорировать остальное")
	}

	if strings.Contains(out, `pull-filter accept "tun-mtu`) {
		t.Fatal("tun-mtu от сервера принимать нельзя")
	}
}

func TestRefusals(t *testing.T) {
	base := vendorFile()
	cases := map[string]string{ //nolint:gosec
		"up /etc/openvpn/update-resolv-conf": "с полными правами",
		"script-security 2":                  "с полными правами",
		"management /tmp/m unix":             "с полными правами",
		"dev-node unix:/tmp/x":               "dev-node",
		"comp-lzo no":                        "формат",
		"compress lz4":                       "формат",
		"fragment 1300":                      "формат",
		"allow-compression yes":              "сжатие",
		"auth-user-pass":                     "логином и паролем",
		"http-proxy 10.0.0.1 3128":           "прокси",
		"pkcs12 client.p12":                  "pkcs12",
		"secret static.key":                  "формат",
		"proto tcp-server":                   "СЕРВЕР",
		"proto udp6":                         "нового поколения",
		"dev tap0":                           "уровня 2",
		"ca ca.crt":                          "единым файлом",
		"remote 2001:db8::1 1194":            "нового поколения",
		"remote 127.0.0.1 1194":              "служебный",
	}
	for extra, want := range cases {
		_, _, err := Parse(base + extra + "\n")
		if err == nil {
			t.Errorf("%q: импорт обязан быть отклонён", extra)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q: текст отказа %q не содержит %q", extra, err.Error(), want)
		}
	}
	for _, block := range []string{"auth-user-pass", "pkcs12", "secret"} {
		_, _, err := Parse(base + "<" + block + ">\nx\n</" + block + ">\n")
		if err == nil {
			t.Errorf("блок %s обязан быть отклонён", block)
		}
	}
}

func TestTCPIsWarnedNotRefused(t *testing.T) {
	p, warnings, err := Parse(strings.Replace(vendorFile(), "proto udp", "proto tcp", 1))
	if err != nil {
		t.Fatalf("TCP — законный выбор, отказ недопустим: %v", err)
	}
	if p.Transport() != vpndriver.TransportTCP || p.Meta().Transport != vpndriver.TransportTCP {
		t.Fatal("транспорт не распознан")
	}
	if !strings.Contains(strings.Join(warnings, " "), "TCP") {
		t.Fatalf("о телефонии по TCP обязаны предупредить: %v", warnings)
	}
	out := string(p.Generate(Render{Iface: TunnelIface, Mark: 1, MTU: 1400}))
	if !strings.Contains(out, "proto tcp-client\n") || strings.Contains(out, "explicit-exit-notify") {
		t.Fatalf("действующий файл по TCP собран неверно:\n%s", out)
	}

	p2, _, err := Parse(strings.Replace(vendorFile(), "remote vpn.example.net 1194", "remote vpn.example.net 443 tcp", 1))
	if err != nil || p2.Transport() != vpndriver.TransportTCP || p2.Remotes[0].Port != 443 {
		t.Fatalf("remote с транспортом: %v %+v", err, p2.Remotes)
	}
}

func TestUnknownOptionWarnsAndSkips(t *testing.T) {
	p, warnings, err := Parse(vendorFile() + "future-knob 42\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "future-knob") {
		t.Fatalf("незнакомая настройка не названа: %v", warnings)
	}
	if strings.Contains(string(p.Library()), "future-knob") {
		t.Fatal("незнакомое не должно попадать в файл")
	}
}

func TestBlockCannotSmuggleCommands(t *testing.T) {
	evil := strings.Replace(vendorFile(), "<ca>\n"+caPEM, "<ca>\n"+caPEM+"\n</ca>\nup /bin/sh\n<ca>\n"+caPEM, 1)
	_, _, err := Parse(evil)
	if err == nil || !strings.Contains(err.Error(), "с полными правами") {
		t.Fatalf("команда внутри «сертификата» прошла: %v", err)
	}
	if _, _, err := Parse(vendorFile() + "<ca>\nx\n</ca>\n"); err == nil || !strings.Contains(err.Error(), "дважды") {
		t.Fatalf("повторный блок: %v", err)
	}
	if _, _, err := Parse(strings.Replace(vendorFile(), "</tls-crypt-v2>", "", 1)); err == nil || !strings.Contains(err.Error(), "не закрыт") {
		t.Fatalf("незакрытый блок: %v", err)
	}
	if _, _, err := Parse(strings.Replace(vendorFile(), "</key>", "", 1)); err == nil || !strings.Contains(err.Error(), "закрыт тегом") {
		t.Fatalf("блок, закрытый чужим тегом: %v", err)
	}
}

func TestMissingCertificateIsRefusedHonestly(t *testing.T) {
	noCert := strings.Replace(vendorFile(), "<cert>\n"+certPEM+"\n</cert>\n", "", 1)
	_, _, err := Parse(noCert)
	if err == nil || !strings.Contains(err.Error(), "логином и паролем") {
		t.Fatalf("без сертификата клиента: %v", err)
	}
	noCA := strings.Replace(vendorFile(), "<ca>\n"+caPEM+"\n</ca>\n", "", 1)
	if _, _, err := Parse(noCA); err == nil || !strings.Contains(err.Error(), "корневого") {
		t.Fatalf("без корневого сертификата: %v", err)
	}

	if _, _, err := Parse(noCA + "peer-fingerprint 00:11:22\n"); err != nil {
		t.Fatalf("отпечаток вместо корня: %v", err)
	}
}

func TestParseStateAndPush(t *testing.T) {
	st, ok := ParseState(">INFO:OpenVPN Management Interface Version 5\n1788793239,CONNECTED,SUCCESS,10.77.77.2,192.168.100.10,1194,,\nEND\n")
	if !ok || !st.Connected || st.LocalIPv4 != "10.77.77.2" || st.Remote != "192.168.100.10" || st.RemotePort != 1194 || st.Unix != 1788793239 {
		t.Fatalf("состояние: %+v %v", st, ok)
	}
	if st2, ok := ParseState("1788793240,RECONNECTING,ping-restart,,,,,\nEND\n"); !ok || st2.Connected {
		t.Fatalf("переподключение — не «подключён»: %+v", st2)
	}
	if _, ok := ParseState(">INFO:hello\nEND\n"); ok {
		t.Fatal("пустой ответ")
	}
	line := "2026-09-07 17:59:19 us=98860 PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.77.77.1,route 192.168.100.0 255.255.255.0,dns server 1 address 10.77.77.1,route-gateway 10.77.77.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.77.77.2 255.255.255.0,peer-id 1,cipher AES-256-GCM,tun-mtu 1500'"
	pushed := ParsePushReply(line)
	if len(pushed) != 12 {
		t.Fatalf("пуш разобран неверно: %v", pushed)
	}
	refused := RefusedPushes(pushed)
	want := []string{"redirect-gateway def1", "dhcp-option DNS 10.77.77.1", "route 192.168.100.0 255.255.255.0", "dns server 1 address 10.77.77.1"}
	if strings.Join(refused, "|") != strings.Join(want, "|") {
		t.Fatalf("отвергнутый пуш: %v", refused)
	}
	if ParsePushReply("nothing here") != nil {
		t.Fatal("чужая строка")
	}
}

func TestSplitArgsQuotes(t *testing.T) {
	got, err := splitArgs(`verify-x509-name "vpn example" name # comment`)
	if err != nil || len(got) != 3 || got[1] != "vpn example" || got[2] != "name" {
		t.Fatalf("кавычки: %v %v", got, err)
	}
	if _, err := splitArgs(`bad "unterminated`); err == nil {
		t.Fatal("незакрытая кавычка")
	}
}

func TestMetaPortFromSeparateLine(t *testing.T) {
	src := strings.Replace(vendorFile(), "remote vpn.example.net 1194\n", "port 443\nremote vpn.example.net\n", 1)
	p, _, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if m := p.Meta(); m.EndpointPort != 443 {
		t.Fatalf("порт в сведениях %d, ждали 443", m.EndpointPort)
	}
	src = strings.Replace(vendorFile(), "remote vpn.example.net 1194\n", "remote vpn.example.net\n", 1)
	if p, _, err = Parse(src); err != nil || p.Meta().EndpointPort != DefaultPort {
		t.Fatalf("без порта — умолчание %d: %v %v", DefaultPort, err, p.Meta().EndpointPort)
	}
}
