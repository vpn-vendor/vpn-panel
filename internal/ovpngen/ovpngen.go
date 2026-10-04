package ovpngen

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/cipherbook"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const TunnelIface = Iface

const (
	DefaultPort = 1194
)

const (
	DefaultPing        = 25
	DefaultPingRestart = 120
)

type ParseError struct{ Text string }

func (e *ParseError) Error() string { return e.Text }

func fail(format string, args ...any) error {
	return &ParseError{Text: fmt.Sprintf(format, args...)}
}

type Remote struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto,omitempty"`
}

func (p *Profile) PortOf(r Remote) int {
	if r.Port != 0 {
		return r.Port
	}
	return p.Port
}

type Option struct {
	Key  string   `json:"key"`
	Args []string `json:"args"`
}

type Profile struct {
	Remotes []Remote `json:"remotes"`

	Proto string `json:"proto"`
	Port  int    `json:"port"`

	Options []Option `json:"options"`

	Inline map[string]string `json:"inline"`

	KeyDirection string `json:"key_direction,omitempty"`

	ConfigDNS []string `json:"config_dns,omitempty"`
	ConfigMTU int      `json:"config_mtu,omitempty"`
	Keepalive int      `json:"keepalive,omitempty"`

	CipherUnfit bool `json:"cipher_unfit,omitempty"`
}

func (p *Profile) Ciphers() []string {
	var out []string
	for _, o := range p.Options {
		switch o.Key {
		case "data-ciphers", "data-ciphers-fallback":
			for _, a := range o.Args {
				out = append(out, cipherbook.SplitList(a)...)
			}
		case "cipher":
			for _, a := range o.Args {
				out = append(out, cipherbook.Canonical(a))
			}
		}
	}
	return dedupe(out)
}

func (p *Profile) Auth() string {
	for _, o := range p.Options {
		if o.Key == "auth" && len(o.Args) == 1 {
			return o.Args[0]
		}
	}
	return ""
}

func (p *Profile) Overhead(ipv6 bool) int { return cipherbook.Overhead(p.Ciphers(), p.Auth(), ipv6) }

func (p *Profile) KernelExpected() bool { return cipherbook.KernelCapable(p.Ciphers()) }

func (p *Profile) VoiceFit() bool { return p.Transport() != vpndriver.TransportTCP && !p.CipherUnfit }

func (p *Profile) Transport() string {
	proto := p.Proto
	if len(p.Remotes) > 0 && p.Remotes[0].Proto != "" {
		proto = p.Remotes[0].Proto
	}
	if proto == vpndriver.TransportTCP {
		return vpndriver.TransportTCP
	}
	return vpndriver.TransportUDP
}

func (p *Profile) Meta() vpndriver.Meta {
	m := vpndriver.Meta{
		Protocol:   ID,
		Transport:  p.Transport(),
		ConfigDNS:  append([]string(nil), p.ConfigDNS...),
		ConfigMTU:  p.ConfigMTU,
		Keepalive:  p.Keepalive,
		FullTunnel: true,
		VoiceFit:   p.VoiceFit(),
	}
	if len(p.Remotes) > 0 {
		m.EndpointHost, m.EndpointPort = p.Remotes[0].Host, p.PortOf(p.Remotes[0])
	}
	if m.Keepalive == 0 {
		m.Keepalive = DefaultPing
	}
	return m
}

var scriptKeys = map[string]bool{
	"up": true, "down": true, "up-pre": true, "route-up": true, "route-pre-down": true,
	"ipchange": true, "tls-verify": true, "client-connect": true, "client-disconnect": true,
	"learn-address": true, "auth-user-pass-verify": true, "plugin": true,
	"script-security": true, "management": true, "management-client": true,
	"management-query-passwords": true, "management-hold": true, "management-signal": true,
	"management-forget-disconnect": true, "management-up-down": true,
	"management-client-auth": true, "management-external-key": true,
	"management-external-cert": true, "management-client-user": true,
	"management-client-group": true, "management-log-cache": true,
	"dns-updown": true, "iproute": true, "tls-export-cert": true,
}

var silentOptions = map[string]bool{
	"dev": true, "dev-type": true, "nobind": true, "persist-key": true, "persist-tun": true,
	"persist-local-ip": true, "persist-remote-ip": true, "verb": true, "mute": true,
	"mute-replay-warnings": true, "suppress-timestamps": true, "resolv-retry": true,
	"explicit-exit-notify": true, "ignore-unknown-option": true, "setenv": true, "setenv-safe": true,
	"connect-retry": true, "connect-retry-max": true, "connect-timeout": true, "server-poll-timeout": true,
	"float": true, "auth-retry": true, "nice": true, "fast-io": true, "sndbuf": true, "rcvbuf": true,
	"socket-flags": true, "txqueuelen": true,
}

var managedOptions = map[string]string{ //nolint:gosec
	"dev": "имя интерфейса", "dev-type": "тип интерфейса",
	"route": "маршруты", "route-ipv6": "маршруты нового поколения", "route-gateway": "шлюз маршрутов",
	"route-metric": "метрику маршрутов", "route-delay": "задержку маршрутов",
	"redirect-gateway": "маршрут по умолчанию", "redirect-private": "маршрут по умолчанию",
	"route-nopull": "приём маршрутов", "route-noexec": "установку маршрутов",
	"pull-filter": "фильтр настроек сервера", "dhcp-option": "настройки сети от сервера",
	"dns": "серверы имён", "block-outside-dns": "блокировку имён", "block-ipv6": "блокировку нового поколения",
	"mark": "служебную метку пакетов", "mssfix": "подгонку сегмента", "tun-mtu": "размер пакетов",
	"link-mtu": "размер кадра", "tun-mtu-extra": "запас размера пакетов",
	"ping": "поддержание связи", "ping-exit": "поддержание связи", "ping-restart": "поддержание связи",
	"keepalive": "поддержание связи", "inactive": "остановку по простою",
	"persist-tun": "сохранение интерфейса", "persist-key": "сохранение ключа",
	"persist-local-ip": "сохранение адреса", "persist-remote-ip": "сохранение адреса",
	"nobind": "привязку порта", "bind": "привязку порта", "local": "адрес привязки", "lport": "порт привязки",
	"daemon": "режим службы", "log": "журнал", "log-append": "журнал", "status": "файл состояния",
	"status-version": "файл состояния", "writepid": "файл процесса", "user": "пользователя процесса",
	"group": "группу процесса", "chroot": "изоляцию процесса", "cd": "рабочий каталог",
	"verb": "подробность журнала", "mute": "подробность журнала", "mute-replay-warnings": "подробность журнала",
	"suppress-timestamps": "подробность журнала", "syslog": "журнал", "errors-to-stderr": "журнал",
	"machine-readable-output": "журнал", "nice": "приоритет процесса",
	"ifconfig": "адрес интерфейса", "ifconfig-ipv6": "адрес интерфейса", "ifconfig-noexec": "адрес интерфейса",
	"ifconfig-nowarn": "адрес интерфейса", "topology": "топологию сети канала",
	"disable-dco": "шифрование в ядре", "txqueuelen": "очередь интерфейса",
	"sndbuf": "буферы сокета", "rcvbuf": "буферы сокета", "socket-flags": "буферы сокета", "fast-io": "режим ввода-вывода",
	"connect-retry": "повторы подключения", "connect-retry-max": "повторы подключения",
	"connect-timeout": "повторы подключения", "server-poll-timeout": "повторы подключения",
	"resolv-retry": "повторы разрешения имени", "explicit-exit-notify": "уведомление о выходе",
	"setenv": "служебные переменные", "setenv-safe": "служебные переменные",
	"push-peer-info": "передачу сведений о системе серверу", "ignore-unknown-option": "обработку незнакомых настроек",
	"allow-recursive-routing": "рекурсивную маршрутизацию", "float": "смену адреса сервера",
	"auth-retry": "повторы входа", "tls-exit": "поведение при ошибке", "single-session": "поведение сессии",
	"passtos": "копирование приоритета", "shaper": "ограничение скорости",
}

var formatKeys = map[string]bool{
	"comp-lzo": true, "compress": true, "comp-noadapt": true, "fragment": true,
	"secret": true, "allow-deprecated-insecure-static-crypto": true,
}

var unsupportedOptions = map[string]string{ //nolint:gosec
	"auth-user-pass":       "подключение с логином и паролем",
	"askpass":              "ввод пароля к ключу",
	"static-challenge":     "ввод одноразового кода",
	"auth-token":           "подключение с логином и паролем",
	"auth-token-user":      "подключение с логином и паролем",
	"http-proxy":           "подключение через прокси",
	"http-proxy-option":    "подключение через прокси",
	"http-proxy-user-pass": "подключение через прокси",
	"socks-proxy":          "подключение через прокси",
	"pkcs12":               "сертификаты в устаревшем формате (pkcs12)",
	"pkcs11-id":            "аппаратный ключ (PKCS#11)",
	"pkcs11-providers":     "аппаратный ключ (PKCS#11)",
	"pkcs11-id-management": "аппаратный ключ (PKCS#11)",
	"cryptoapicert":        "сертификаты из хранилища Windows",
}

var deprecatedKeys = map[string]bool{
	"ns-cert-type": true, "verify-hash": true,
}

var allowedKeys = map[string]bool{
	"client": true, "tls-client": true, "pull": true,
	"remote-cert-tls": true, "remote-cert-eku": true, "remote-cert-ku": true,
	"verify-x509-name": true, "tls-version-min": true, "tls-version-max": true,
	"tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true, "tls-cert-profile": true,
	"data-ciphers": true, "data-ciphers-fallback": true, "cipher": true, "auth": true,
	"auth-nocache": true, "reneg-sec": true, "hand-window": true,
	"tls-timeout": true, "replay-window": true, "ecdh-curve": true, "providers": true,
	"remote-random": true, "peer-fingerprint": true, "ns-cert-type": true, "verify-hash": true,
	"allow-compression": true, "x509-username-field": true, "compat-mode": true,
}

var fileRefOptions = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "extra-certs": true, "crl-verify": true, "dh": true,
}

var (
	allowedBlocks = map[string]bool{
		"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
		"tls-crypt-v2": true, "extra-certs": true, "crl-verify": true, "peer-fingerprint": true,
	}
	skippedBlocks = map[string]string{
		"dh": "параметры Диффи — Хеллмана нужны только серверу",
	}
	refusedBlocks = map[string]string{ //nolint:gosec
		"pkcs12":               "сертификаты в устаревшем формате (pkcs12)",
		"auth-user-pass":       "подключение с логином и паролем",
		"http-proxy-user-pass": "подключение через прокси",
		"secret":               "статический ключ",
	}
)

var (
	blockOpenRe  = regexp.MustCompile(`^<([a-z0-9-]{1,32})>$`)
	blockCloseRe = regexp.MustCompile(`^</([a-z0-9-]{1,32})>$`)

	argRe = regexp.MustCompile(`^[A-Za-z0-9:._+/=@,%-]+$`)

	spacedArgRe = regexp.MustCompile(`^[A-Za-z0-9 :._+/=@,%*-]+$`)
	spacedKeys  = map[string]bool{"remote-cert-eku": true, "verify-x509-name": true, "tls-cert-profile": true, "x509-username-field": true}

	blockLineRe = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

const MaxBlockLines = 2000

func Parse(text string) (*Profile, []string, error) {
	if len(text) > vpndriver.MaxConfigBytes {
		return nil, nil, fail("файл слишком большой для конфигурации подключения — проверьте, что выбран нужный файл")
	}
	if msg := vpndriver.ShapeError(text); msg != "" {
		return nil, nil, fail("%s", msg)
	}
	p := &Profile{Inline: map[string]string{}, Port: DefaultPort, Proto: vpndriver.TransportUDP}
	var (
		warnings []string
		unknown  []string
		managed  []string
		seenKey  = map[string]bool{}

		ncpAliased bool
	)
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(strings.TrimSuffix(lines[i], "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if m := blockOpenRe.FindStringSubmatch(line); m != nil {
			tag := m[1]
			body, next, err := readBlock(lines, i+1, tag)
			if err != nil {
				return nil, nil, err
			}
			i = next
			switch {
			case refusedBlocks[tag] != "":
				return nil, nil, fail("в файле есть %s — эта версия панели такие подключения не поддерживает. Запросите у поставщика файл со всеми сертификатами внутри и без логина и пароля", refusedBlocks[tag])
			case skippedBlocks[tag] != "":
				warnings = append(warnings, "блок «"+tag+"» пропущен: "+skippedBlocks[tag])
			case allowedBlocks[tag]:
				if _, dup := p.Inline[tag]; dup {
					return nil, nil, fail("блок «%s» встречается в файле дважды — исправьте файл или запросите его заново", tag)
				}
				p.Inline[tag] = body
			default:
				warnings = append(warnings, "блок «"+tag+"» этой версией панели не поддерживается и пропущен")
			}
			continue
		}
		if strings.HasPrefix(line, "<") {
			return nil, nil, fail("строка %d файла не похожа на настройку — проверьте, что выбран файл подключения", i+1)
		}
		args, err := splitArgs(line)
		if err != nil || len(args) == 0 {
			return nil, nil, fail("строка %d файла не похожа на настройку — проверьте, что выбран файл подключения", i+1)
		}
		key := strings.ToLower(args[0])
		vals := args[1:]

		if scriptKeys[key] {
			return nil, nil, fail("в файле есть команда «%s», которую сервер выполнил бы с полными правами. Такие файлы панель не принимает — запросите у поставщика конфигурацию без встроенных команд", args[0])
		}
		if key == "dev-node" {
			return nil, nil, fail("в файле есть настройка «dev-node», которая указывает на устройство или программу. Такие файлы панель не принимает — запросите конфигурацию без неё")
		}

		if formatKeys[key] {
			return nil, nil, fail("файл рассчитан на канал с особым форматом пакетов (настройка «%s»: сжатие, дробление или статический ключ). Эта версия панели работает с обычным каналом: если импортировать файл как есть, канал поднимется, но работать не будет. Запросите у поставщика обычную конфигурацию", args[0])
		}
		if key == "allow-compression" && (len(vals) != 1 || strings.ToLower(vals[0]) != "no") {
			return nil, nil, fail("файл разрешает сжатие в канале (настройка «allow-compression»). Эта версия панели работает без сжатия: с ним канал поднимется, но работать не будет. Запросите у поставщика конфигурацию без сжатия")
		}
		if what, ok := unsupportedOptions[key]; ok {
			return nil, nil, fail("в файле есть %s (настройка «%s») — эта версия панели такие подключения не поддерживает. Запросите у поставщика файл со всеми сертификатами внутри и без логина и пароля", what, args[0])
		}
		if fileRefOptions[key] {
			if len(vals) >= 1 && strings.EqualFold(vals[0], "[inline]") {

				if key == "tls-auth" && len(vals) >= 2 {
					p.KeyDirection = vals[1]
				}
				continue
			}
			return nil, nil, fail("файл ссылается на другой файл («%s»): такие конфигурации панель не принимает. Запросите у поставщика конфигурацию единым файлом — со всеми сертификатами внутри", args[0])
		}

		switch key {
		case "proto":
			proto, perr := parseProto(vals)
			if perr != nil {
				return nil, nil, perr
			}
			p.Proto = proto
			continue
		case "port", "rport":
			port, perr := parsePort(vals)
			if perr != nil {
				return nil, nil, fail("порт в файле записан неверно: %s", perr)
			}
			p.Port = port
			continue
		case "remote":
			r, rerr := parseRemote(vals)
			if rerr != nil {
				return nil, nil, rerr
			}
			p.Remotes = append(p.Remotes, r)
			continue
		case "dev", "dev-type":
			if len(vals) >= 1 && strings.HasPrefix(strings.ToLower(vals[0]), "tap") {
				return nil, nil, fail("файл описывает канал уровня 2 (tap) — такие подключения панель не поддерживает. Запросите у поставщика обычную конфигурацию (tun)")
			}
		case "dhcp-option":
			if len(vals) >= 2 && strings.EqualFold(vals[0], "DNS") {
				if ip := net.ParseIP(vals[1]); ip != nil {
					p.ConfigDNS = append(p.ConfigDNS, ip.String())
				}
			}
		case "tun-mtu":
			if len(vals) == 1 {
				if n, aerr := strconv.Atoi(vals[0]); aerr == nil && n >= vpndriver.MinMTU && n <= vpndriver.MaxMTU {
					p.ConfigMTU = n
				} else {
					warnings = append(warnings, fmt.Sprintf("файл просит размер пакетов «%s» — это вне допустимых значений (%d…%d), панель подберёт его сама", vals[0], vpndriver.MinMTU, vpndriver.MaxMTU))
				}
			}
		case "keepalive", "ping":
			if len(vals) >= 1 {
				if n, aerr := strconv.Atoi(vals[0]); aerr == nil && n > 0 {
					p.Keepalive = n
				}
			}
		}
		if silentOptions[key] {
			continue
		}
		if human, ok := managedOptions[key]; ok {
			managed = append(managed, human)
			continue
		}

		switch key {
		case "ncp-ciphers":
			key = "data-ciphers"
			if seenKey[key] {
				warnings = append(warnings, "устаревшая запись «ncp-ciphers» пропущена: в файле есть её современный аналог")
				continue
			}
			ncpAliased = true
			warnings = append(warnings, "устаревшая запись «ncp-ciphers» прочитана как современный аналог")
		case "data-ciphers":
			if seenKey[key] && ncpAliased {

				for i, o := range p.Options {
					if o.Key == "data-ciphers" {
						p.Options = append(p.Options[:i], p.Options[i+1:]...)
						break
					}
				}
				delete(seenKey, key)
				ncpAliased = false
				warnings = append(warnings, "устаревшая запись «ncp-ciphers» пропущена: в файле есть её современный аналог")
			}
		case "tls-remote":
			if len(vals) != 1 {
				return nil, nil, fail("устаревшая запись «tls-remote» записана неверно — запросите конфигурацию заново")
			}
			key, vals = "verify-x509-name", []string{vals[0], "name-prefix"}
			warnings = append(warnings, "устаревшая запись «tls-remote» прочитана как современный аналог проверки имени сервера")
		case "tls-version-min":
			if len(vals) >= 1 && (vals[0] == "1.0" || vals[0] == "1.1") {
				vals = append([]string{"1.2"}, vals[1:]...)
				warnings = append(warnings, "файл допускал устаревшие версии TLS — панель применила минимум 1.2, который и так действует у современных серверов")
			}
		}
		if key == "key-direction" {
			if len(vals) != 1 || (vals[0] != "0" && vals[0] != "1") {
				return nil, nil, fail("направление ключа в файле записано неверно — запросите конфигурацию заново")
			}
			p.KeyDirection = vals[0]
			warnings = append(warnings, "настройка «key-direction» устарела, но пока работает — панель её сохранила")
			continue
		}
		if allowedKeys[key] {
			if deprecatedKeys[key] {
				warnings = append(warnings, "настройка «"+args[0]+"» устарела в этой версии протокола, но пока работает — панель её сохранила")
			}
			re := argRe
			if spacedKeys[key] {
				re = spacedArgRe
			}
			for _, v := range vals {
				if !re.MatchString(v) {
					return nil, nil, fail("значение настройки «%s» содержит недопустимые символы — запросите конфигурацию заново", args[0])
				}
			}
			if seenKey[key] && key != "remote" {
				return nil, nil, fail("настройка «%s» встречается в файле дважды — исправьте файл или запросите его заново", args[0])
			}
			seenKey[key] = true
			p.Options = append(p.Options, Option{Key: key, Args: append([]string(nil), vals...)})
			continue
		}
		unknown = append(unknown, args[0])
	}

	if len(managed) > 0 {
		warnings = append(warnings, "файл задаёт "+strings.Join(dedupe(managed), ", ")+" — этим распоряжается сама панель, значения из файла пропущены")
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		warnings = append(warnings, "файл содержит настройки, которых эта версия панели не знает ("+strings.Join(dedupe(unknown), ", ")+") — они пропущены, подключение это не ломает")
	}
	if err := p.validate(); err != nil {
		return nil, nil, err
	}

	switch verdict := cipherbook.Classify(p.Ciphers(), p.Auth()); {
	case verdict.Fitness == cipherbook.Refuse:
		return nil, nil, fail("файл использует устаревший или небезопасный способ шифрования (%s) — эта версия панели его не поддерживает. Запросите у поставщика свежий файл", strings.Join(verdict.Refused, ", "))
	case verdict.Fitness == cipherbook.Unfit:
		p.CipherUnfit = true
		warnings = append(warnings, "способ шифрования в файле не годится для разговоров: под нагрузкой они будут страдать. Для телефонии запросите у поставщика современный файл")
	case verdict.Mixed:
		warnings = append(warnings, "среди способов шифрования в файле есть неподходящие для разговоров; какой выберет сервер — решает сервер. Панель покажет это после подключения")
	}
	if p.Transport() == vpndriver.TransportTCP {

		warnings = append(warnings, "подключение работает по TCP: для работы в интернете годится, а разговоры через него будут страдать — при потере пакета задерживается всё, что идёт следом. Для телефонии запросите у поставщика подключение по UDP")
	}
	if len(p.ConfigDNS) > 0 {
		warnings = append(warnings, "файл просит сервер имён "+strings.Join(p.ConfigDNS, ", ")+" — по умолчанию панель его не применяет: именами офиса распоряжается резолвер шлюза")
	}
	if len(p.Remotes) > 1 {
		warnings = append(warnings, fmt.Sprintf("в файле %d серверов — панель будет пробовать их по очереди, начиная с первого", len(p.Remotes)))
	}
	return p, warnings, nil
}

func (p *Profile) validate() error {
	switch {
	case len(p.Remotes) == 0:
		return fail("в файле нет адреса сервера (строки «remote») — это не файл подключения либо он неполный")
	case p.Inline["ca"] == "" && p.Inline["peer-fingerprint"] == "" && !p.hasOption("peer-fingerprint"):
		return fail("в файле нет корневого сертификата (блока «ca») и отпечатка сервера — проверить сервер было бы нечем; запросите конфигурацию заново")
	case p.Inline["cert"] == "" || p.Inline["key"] == "":
		return fail("в файле нет сертификата и ключа клиента (блоков «cert» и «key») — такие подключения (с логином и паролем) эта версия панели не поддерживает. Запросите у поставщика файл со всеми сертификатами внутри")
	}
	for _, r := range p.Remotes {
		if ip := net.ParseIP(r.Host); ip != nil && !vpndriver.UsableEndpoint(ip) {
			return fail("адрес сервера в файле служебный (петля, широковещательный или пустой) — по такому адресу подключение не работает; запросите конфигурацию заново")
		}
	}
	return nil
}

func (p *Profile) hasOption(key string) bool {
	for _, o := range p.Options {
		if o.Key == key {
			return true
		}
	}
	return false
}

func readBlock(lines []string, from int, tag string) (string, int, error) {
	var body []string
	for i := from; i < len(lines); i++ {
		line := strings.TrimRight(strings.TrimSuffix(lines[i], "\r"), " \t")
		if m := blockCloseRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if m[1] != tag {
				return "", 0, fail("блок «%s» закрыт тегом «%s» — файл повреждён, запросите его заново", tag, m[1])
			}
			return strings.Join(body, "\n"), i, nil
		}
		if !blockLineRe.MatchString(line) {
			return "", 0, fail("блок «%s» содержит недопустимые символы — файл повреждён, запросите его заново", tag)
		}
		if len(body) >= MaxBlockLines {
			return "", 0, fail("блок «%s» слишком длинный для сертификата — проверьте, что выбран нужный файл", tag)
		}
		body = append(body, line)
	}
	return "", 0, fail("блок «%s» не закрыт — файл обрезан или повреждён, запросите его заново", tag)
}

func splitArgs(line string) ([]string, error) {
	var (
		out   []string
		cur   strings.Builder
		inArg bool
		quote rune
	)
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && i+1 < len(rs) {
				i++
				cur.WriteRune(rs[i])
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inArg = r, true
		case r == '\\' && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
			inArg = true
		case r == ' ' || r == '\t':
			if inArg {
				out = append(out, cur.String())
				cur.Reset()
				inArg = false
			}
		case r == '#' || r == ';':

			if inArg {
				out = append(out, cur.String())
			}
			return out, nil
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("незакрытая кавычка")
	}
	if inArg {
		out = append(out, cur.String())
	}
	return out, nil
}

func parseProto(vals []string) (string, error) {
	if len(vals) != 1 {
		return "", fail("транспорт в файле записан неверно — запросите конфигурацию заново")
	}
	switch strings.ToLower(vals[0]) {
	case "udp", "udp4":
		return vpndriver.TransportUDP, nil
	case "tcp", "tcp4", "tcp-client", "tcp4-client":
		return vpndriver.TransportTCP, nil
	case "tcp-server", "tcp4-server", "tcp6-server":
		return "", fail("файл описывает СЕРВЕР, а не подключение к нему — это не файл клиента")
	case "udp6", "tcp6", "tcp6-client":
		return "", fail("файл требует подключение по адресу нового поколения (IPv6) — эта версия панели такие подключения не поддерживает")
	}
	return "", fail("транспорт «%s» в файле не поддерживается — запросите конфигурацию заново", vals[0])
}

func parsePort(vals []string) (int, error) {
	if len(vals) != 1 {
		return 0, fmt.Errorf("нужно одно число")
	}
	port, err := strconv.Atoi(vals[0])
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("номер порта «%s» вне допустимых значений", vals[0])
	}
	return port, nil
}

func parseRemote(vals []string) (Remote, error) {
	if len(vals) < 1 || len(vals) > 3 {
		return Remote{}, fail("адрес сервера в файле записан неверно: нужен вид «remote адрес [порт] [udp|tcp]»")
	}
	r := Remote{Host: strings.ToLower(vals[0])}
	if ip := net.ParseIP(r.Host); ip != nil {
		if ip.To4() == nil {
			return Remote{}, fail("адрес сервера в файле — адрес нового поколения (IPv6); эта версия панели такие подключения не поддерживает")
		}
		r.Host = ip.To4().String()
	} else if !vpndriver.ValidHostname(r.Host) {
		return Remote{}, fail("«%s» не похоже на имя или адрес сервера", vals[0])
	}
	if len(vals) >= 2 {
		port, err := parsePort(vals[1:2])
		if err != nil {
			return Remote{}, fail("порт сервера в файле записан неверно: %s", err)
		}
		r.Port = port
	}
	if len(vals) == 3 {
		proto, err := parseProto(vals[2:3])
		if err != nil {
			return Remote{}, err
		}
		r.Proto = proto
	}
	return r, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (p *Profile) Library() []byte {
	var b strings.Builder
	b.WriteString("client\n")
	if p.Proto != "" {
		b.WriteString("proto " + protoLine(p.Proto) + "\n")
	}
	if p.Port != DefaultPort {
		b.WriteString("port " + strconv.Itoa(p.Port) + "\n")
	}
	for _, r := range p.Remotes {
		b.WriteString(renderRemote(r, p.Port, p.Proto))
	}
	p.writeOptions(&b)
	p.writeBlocks(&b)
	return []byte(b.String())
}

type Render struct {
	Iface string
	Mark  int
	MTU   int

	Remotes []Remote

	Management string
}

func (p *Profile) Generate(r Render) []byte {
	remotes := p.Remotes
	if len(r.Remotes) > 0 {
		remotes = r.Remotes
	}
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev " + r.Iface + "\n")
	b.WriteString("dev-type tun\n")
	if p.Proto != "" {
		b.WriteString("proto " + protoLine(p.Proto) + "\n")
	}
	for _, rm := range remotes {
		b.WriteString(renderRemote(rm, p.Port, p.Proto))
	}
	b.WriteString("nobind\n")

	b.WriteString("resolv-retry infinite\n")

	b.WriteString("mark " + strconv.Itoa(r.Mark) + "\n")

	b.WriteString("route-noexec\n")
	b.WriteString("route-nopull\n")
	b.WriteString("dns-updown disable\n")

	for _, accept := range pushAccept {
		b.WriteString("pull-filter accept \"" + accept + "\"\n")
	}
	for _, reject := range pushReject {
		b.WriteString("pull-filter reject \"" + reject + "\"\n")
	}
	b.WriteString("pull-filter ignore \"\"\n")
	b.WriteString("ping " + strconv.Itoa(DefaultPing) + "\n")
	b.WriteString("ping-restart " + strconv.Itoa(DefaultPingRestart) + "\n")
	b.WriteString("tun-mtu " + strconv.Itoa(r.MTU) + "\n")
	if p.Transport() == vpndriver.TransportUDP {
		b.WriteString("explicit-exit-notify 1\n")
	}
	if r.Management != "" {
		b.WriteString("management " + r.Management + " unix\n")
		b.WriteString("management-client-user root\n")
	}
	b.WriteString("verb 3\n")
	p.writeOptions(&b)
	p.writeBlocks(&b)
	return []byte(b.String())
}

var pushAccept = []string{
	"ifconfig ", "topology ", "route-gateway ", "ping", "peer-id ", "cipher ", "protocol-flags",
}

var pushReject = []string{"compress", "comp-lzo", "fragment"}

func protoLine(proto string) string {
	if proto == vpndriver.TransportTCP {
		return "tcp-client"
	}
	return proto
}

func renderRemote(r Remote, defPort int, defProto string) string {
	port := r.Port
	if port == 0 {
		port = defPort
	}
	proto := r.Proto
	if proto == "" {
		proto = defProto
	}
	line := "remote " + r.Host + " " + strconv.Itoa(port)
	if proto != "" {
		line += " " + proto
	}
	return line + "\n"
}

func (p *Profile) writeOptions(b *strings.Builder) {
	for _, o := range p.Options {
		if o.Key == "client" || o.Key == "tls-client" || o.Key == "pull" {
			continue
		}
		b.WriteString(o.Key)
		for _, a := range o.Args {
			if strings.ContainsAny(a, " \t") {
				b.WriteString(" \"" + a + "\"")
			} else {
				b.WriteString(" " + a)
			}
		}
		b.WriteString("\n")
	}
	if p.KeyDirection != "" {
		b.WriteString("key-direction " + p.KeyDirection + "\n")
	}
}

func (p *Profile) writeBlocks(b *strings.Builder) {
	tags := make([]string, 0, len(p.Inline))
	for tag := range p.Inline {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		b.WriteString("<" + tag + ">\n" + p.Inline[tag] + "\n</" + tag + ">\n")
	}
}
