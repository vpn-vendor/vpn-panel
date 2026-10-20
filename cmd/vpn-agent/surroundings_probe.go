package main

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/sockowner"
)

const (
	factHTTPPort    = "surroundings.http_port"
	factTLSPort     = "surroundings.tls_port"
	factDHCPHost    = "surroundings.dhcp_host"
	factForwardBoot = "surroundings.forward_boot"
	factLegacy      = "legacy.gateway"
	factLegacySudo  = "legacy.danger.sudo"
	factLegacyRoot  = "legacy.danger.root_service"
	factLegacyTerm  = "legacy.danger.terminal"
	factLegacyUSB   = "legacy.danger.usb"
	factLegacyKeys  = "legacy.danger.keys"
	factLegacyPPPoE = "legacy.pppoe"
	factLegacyTun   = "legacy.tunnel"
	factLegacyRerun = "legacy.rerun"
	factLegacyRun   = "legacy.running"
)

const keaUnit = "kea-dhcp4-server"

func surroundUnits() []string {
	out := append([]string{keaUnit}, dhcpServers...)
	out = append(out, ruleSourceUnits...)
	for _, u := range legacyvpn.Units() {
		u = strings.TrimSuffix(u, ".service")
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

func surroundProbeSet() []surroundProbe {
	return []surroundProbe{
		{ids: []string{factHTTPPort, factTLSPort}, run: probePanelPorts},
		{ids: []string{factDHCPHost}, run: probeDHCPHost},
		{ids: []string{factForwardBoot}, run: probeForwardBoot},
		{ids: []string{factLegacy, factLegacySudo, factLegacyRoot, factLegacyTerm, factLegacyUSB,
			factLegacyKeys, factLegacyPPPoE, factLegacyTun, factLegacyRerun, factLegacyRun}, run: probeLegacy},
	}
}

func foreign(id, title, how string) hostcaps.Fact {
	return hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: hostcaps.Unknown, How: how, Title: title}
}

var programNames = map[string]string{
	"apache2": "Apache", "httpd": "Apache", "nginx": "nginx", "lighttpd": "lighttpd", "caddy": "Caddy",
	"haproxy": "HAProxy", "docker-proxy": "Docker", "dhcpd": "ISC DHCP", "dnsmasq": "dnsmasq",
	"udhcpd": "udhcpd", "shellinaboxd": "shellinabox",
}

func programName(comm string) string {
	if n, ok := programNames[comm]; ok {
		return n
	}
	return comm
}

func panelPorts(root string) (httpPort, tlsPort int) {
	httpPort, tlsPort = 80, 443
	data, err := os.ReadFile(filepath.Join(root, panelEnv)) //nolint:gosec
	if err != nil {
		return httpPort, tlsPort
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"'`))
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		switch k {
		case "APP_PORT":
			httpPort = n
		case "APP_TLS_PORT":
			tlsPort = n
		}
	}
	return httpPort, tlsPort
}

func blocksLocal(a netip.Addr) bool {
	return a.IsUnspecified() || a == netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

func blocksPanel(a netip.Addr) bool {
	return a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

type portHolder struct {
	Name, Unit string
	Support    []string
	Found, OK  bool
}

func portOwner(root string, port int, blocks func(netip.Addr) bool) portHolder {
	var h portHolder
	socks, err := sockowner.List(root, "tcp", port)
	if err != nil {
		return h
	}
	inodes := make([]uint64, 0, len(socks))
	for _, s := range socks {
		inodes = append(inodes, s.Inode)
	}
	owners, err := sockowner.Owners(root, inodes)
	if err != nil {
		return h
	}
	h.OK = true
	for _, s := range socks {
		o, known := owners[s.Inode]
		line := s.Addr.String() + ":" + strconv.Itoa(port) + " " + o.Comm + " " + o.Unit
		if known && o.Unit == panelUnit {
			continue
		}
		if !blocks(s.Addr) {
			h.Support = append(h.Support, line+" (панели не мешает)")
			continue
		}
		if !known {

			h.OK = false
			continue
		}
		if !h.Found {
			h.Name, h.Unit = programName(o.Comm), o.Unit
		}
		h.Found = true
		h.Support = append(h.Support, line)
	}
	h.OK = h.OK || h.Found
	return h
}

func probePanelPorts(_ context.Context, env surroundEnv) []observation {
	httpPort, tlsPort := panelPorts(env.root)
	return seen(
		portFact(env, factHTTPPort, httpPort, "Короткий адрес панели", hostcaps.LevelWarn,
			"Порт "+strconv.Itoa(httpPort)+" занят программой %s: адрес с http:// открывает её, а не панель. Панель работает по адресу с https://. Чтобы короткий адрес вёл в панель, выключите %s."),
		portFact(env, factTLSPort, tlsPort, "Порт панели", hostcaps.LevelError,
			"Порт "+strconv.Itoa(tlsPort)+" занят программой %s: панель недоступна. Выключите %s — перезапуск панели не поможет."),
	)
}

func portFact(env surroundEnv, id string, port int, title, level, found string) hostcaps.Fact {
	f := foreign(id, title, hostcaps.HowSocket)
	h := portOwner(env.root, port, blocksPanel)
	switch {
	case h.Found:
		f.Answer, f.Value, f.Level, f.Support = hostcaps.Yes, h.Name, level, h.Support
		f.Found = strings.ReplaceAll(found, "%s", h.Name)

		if h.Unit == "apache2.service" && env.legacyGateway() {
			f.Cause = hostcaps.CauseLegacy
			if id == factHTTPPort {
				f.Found = "Порт " + strconv.Itoa(port) + " занят веб-сервером Apache старого скрипта vpn.sh: адрес с http:// открывает старую панель. Новая панель открывается по адресу с https://."
			}
		}
	case h.OK:
		f.Answer, f.Support = hostcaps.No, h.Support
	}
	return f
}

func panelPortTaken() string {
	_, tls := panelPorts("/")
	if h := portOwner("/", tls, blocksLocal); h.Found {
		return h.Name
	}
	return ""
}

type foreignDHCP struct {
	Found bool
	Name  string

	Cards   []string
	Support []string
	Legacy  bool

	OwnCards []string

	UnitsUnknown bool
}

var dhcpServers = []string{"isc-dhcp-server", "dnsmasq", "udhcpd"}

var dhcpServerNames = map[string]string{"isc-dhcp-server": "ISC DHCP", "dnsmasq": "dnsmasq", "udhcpd": "udhcpd"}

func scanForeignDHCP(env surroundEnv, cardOf func(netip.Addr) string) (foreignDHCP, bool) {
	var r foreignDHCP
	socks, err := sockowner.List(env.root, "udp", 67)
	if err != nil {
		return r, false
	}
	inodes := make([]uint64, 0, len(socks))
	for _, s := range socks {
		inodes = append(inodes, s.Inode)
	}
	owners, err := sockowner.Owners(env.root, inodes)
	if err != nil {
		return r, false
	}
	cards := map[string]bool{}
	isc := false
	for _, s := range socks {
		o, known := owners[s.Inode]
		if known && o.Unit == keaUnit+".service" {
			if c := cardOf(s.Addr); c != "" && !slices.Contains(r.OwnCards, c) {
				r.OwnCards = append(r.OwnCards, c)
			}
			continue
		}
		r.Found = true
		if known && r.Name == "" {
			r.Name = programName(o.Comm)
		}
		r.Support = append(r.Support, s.Addr.String()+":67 "+o.Comm+" "+o.Unit)
		if !known {

			continue
		}
		unit := strings.TrimSuffix(o.Unit, ".service")
		if env.skip != nil && env.skip(unit) {
			continue
		}
		isc = isc || unit == "isc-dhcp-server"
		if !s.Addr.IsUnspecified() {
			if c := cardOf(s.Addr); c != "" {
				cards[c] = true
			}
			continue
		}
		cc, files := dhcpConfigCards(env.root, unit)
		for _, c := range cc {
			cards[c] = true
		}
		if len(cc) > 0 {
			r.Support = append(r.Support, "конфиг "+strings.Join(files, ", ")+": "+strings.Join(cc, ","))
		}
	}

	r.UnitsUnknown = !env.unitsKnown
	for _, unit := range dhcpServers {
		if !env.unitsKnown || !env.units(unit).Enabled || (env.skip != nil && env.skip(unit)) {
			continue
		}
		cc, files := dhcpConfigCards(env.root, unit)
		if len(cc) == 0 {
			continue
		}
		r.Found = true
		isc = isc || unit == "isc-dhcp-server"
		if r.Name == "" {
			r.Name = dhcpServerNames[unit]
		}
		r.Support = append(r.Support, unit+" включена, конфиг "+strings.Join(files, ", ")+": "+strings.Join(cc, ","))
		for _, c := range cc {
			cards[c] = true
		}
	}
	for c := range cards {
		r.Cards = append(r.Cards, c)
	}
	sort.Strings(r.Cards)
	sort.Strings(r.OwnCards)

	r.Legacy = isc && env.legacyGateway()
	if r.Name == "" {
		r.Name = "неизвестная программа"
	}
	return r, true
}

func (r foreignDHCP) touches(lans []string) bool {
	for _, c := range r.Cards {
		if c == "*" {
			return len(lans) > 0
		}
		if slices.Contains(lans, c) {
			return true
		}
	}
	return false
}

func (r foreignDHCP) ownServes(lans []string) bool {
	for _, l := range lans {
		if !slices.Contains(r.OwnCards, l) {
			return false
		}
	}
	return len(lans) > 0
}

func dhcpConfigCards(root, unit string) (cards, files []string) {
	switch unit {
	case "isc-dhcp-server":
		const p = "/etc/default/isc-dhcp-server"
		if c := shellVarWords(filepath.Join(root, p), "INTERFACESv4", "INTERFACES"); len(c) > 0 {
			return c, []string{p}
		}
	case "dnsmasq":
		return dnsmasqCards(root)
	case "udhcpd":
		const p = "/etc/udhcpd.conf"
		if c := keyWords(filepath.Join(root, p), "interface"); len(c) > 0 {
			return c, []string{p}
		}
	}
	return nil, nil
}

func shellVarWords(path string, names ...string) []string {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil
	}
	for _, name := range names {
		for _, line := range strings.Split(string(data), "\n") {
			v, ok := strings.CutPrefix(strings.TrimSpace(line), name+"=")
			if !ok {
				continue
			}
			if words := strings.Fields(strings.Trim(v, `"'`)); len(words) > 0 {
				return words
			}
		}
	}
	return nil
}

func keyWords(path, key string) []string {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == key {
			out = append(out, f[1])
		}
	}
	return out
}

func dnsmasqCards(root string) (cards, files []string) {
	paths := []string{"/etc/dnsmasq.conf"}
	more, _ := filepath.Glob(filepath.Join(root, "etc/dnsmasq.d/*.conf"))
	for _, m := range more {
		paths = append(paths, strings.TrimPrefix(m, filepath.Clean(root)))
	}
	dhcp := false
	for _, p := range paths {
		data, err := os.ReadFile(filepath.Join(root, p)) //nolint:gosec
		if err != nil {
			continue
		}
		used := false
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "dhcp-range") {
				dhcp, used = true, true
			}
			if v, ok := strings.CutPrefix(line, "interface="); ok {
				cards = append(cards, strings.Split(v, ",")...)
				used = true
			}
		}
		if used {
			files = append(files, p)
		}
	}
	if !dhcp {
		return nil, nil
	}
	if len(cards) == 0 {
		return []string{"*"}, files
	}
	return cards, files
}

func cardOfAddr(a netip.Addr) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr() == a {
				return i.Name
			}
		}
	}
	return ""
}

func probeDHCPHost(_ context.Context, env surroundEnv) []observation {
	f := foreign(factDHCPHost, "Раздача адресов на этом сервере", hostcaps.HowSocket)
	if env.awaiting() {

		return []observation{{Fact: f, hold: true}}
	}
	moving := env.units(keaUnit).Moving
	r, ok := scanForeignDHCP(env, cardOfAddr)
	switch {
	case !ok:
	case !r.Found && r.UnitsUnknown:

	case !r.Found:
		f.Answer = hostcaps.No
	default:
		f.Answer, f.Value, f.Cards, f.Support = hostcaps.Yes, r.Name, r.Cards, r.Support
		f.Found, f.Level = dhcpFoundText(r), hostcaps.LevelError
		if len(r.Cards) == 0 {
			f.Level = hostcaps.LevelInfo
		}
		if r.Legacy {
			f.Cause = hostcaps.CauseLegacy
		}
	}
	return []observation{{Fact: f, moving: moving}}
}

func dhcpFoundText(r foreignDHCP) string {
	if len(r.Cards) == 0 {
		return "На этом сервере работает ещё одна служба раздачи адресов (" + r.Name + "). Карту, на которой она раздаёт, определить не удалось; если это не сеть офиса, делать ничего не нужно."
	}
	where := "на карте " + strings.Join(r.Cards, ", ")
	if r.Cards[0] == "*" {
		where = "на всех картах"
	}
	text := "На этом сервере работает другая служба раздачи адресов (" + r.Name + ") " + where +
		". Пока она включена, раздачу адресов панели на этой карте включить нельзя: после перезагрузки адреса раздавал бы то один сервер, то другой."
	if r.Legacy {
		return text + " Это служба старого скрипта vpn.sh: офис продолжает получать адреса от неё, сеть панели пока не применяется."
	}
	return text + " Выключите эту службу или перенесите её на другую карту."
}

func dhcpNeighbourText(r foreignDHCP) string {
	return "На карте офиса кроме шлюза включена ещё одна служба раздачи адресов (" + r.Name +
		"): после перезагрузки устройства могут получить адрес от неё. Выключите её."
}

func (s *surroundings) dhcpConflict(lans []string, doomed ...string) (foreignDHCP, bool) {
	if s == nil || len(lans) == 0 {
		return foreignDHCP{}, false
	}
	env := s.env
	units, known := s.queryUnits()
	env.units, env.unitsKnown = func(u string) svcState { return units[u] }, known

	if len(doomed) > 0 {
		inner := env.skip
		env.skip = func(unit string) bool {
			return slices.Contains(doomed, strings.TrimSuffix(unit, ".service")) || (inner != nil && inner(unit))
		}
	}
	r, ok := scanForeignDHCP(env, cardOfAddr)
	if !ok || !r.Found {
		return r, false
	}
	return r, r.touches(lans)
}

var sysctlDirs = []string{"etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d"}

func forwardBootFiles(root string) []string {
	byName := map[string]string{}
	for _, dir := range sysctlDirs {
		paths, _ := filepath.Glob(filepath.Join(root, dir, "*.conf"))
		for _, p := range paths {
			if _, taken := byName[filepath.Base(p)]; !taken {
				byName[filepath.Base(p)] = p
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	order := make([]string, 0, len(names)+1)
	done := map[string]bool{}
	for _, n := range names {
		real, err := filepath.EvalSymlinks(byName[n])
		if err != nil || real == "/dev/null" || done[real] {

			continue
		}
		done[real] = true
		order = append(order, real)
	}
	if real, err := filepath.EvalSymlinks(filepath.Join(root, "etc/sysctl.conf")); err == nil && !done[real] {
		order = append(order, real)
	}
	var on []string
	for _, p := range order {
		switch forwardSetting(p) {
		case "1":
			on = append(on, strings.TrimPrefix(p, filepath.Clean(root)))
		case "0":
			on = nil
		}
	}
	return on
}

func forwardSetting(path string) string {
	fh, err := os.Open(path) //nolint:gosec
	if err != nil {
		return ""
	}
	defer func() { _ = fh.Close() }()
	last := ""
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimPrefix(strings.TrimSpace(sc.Text()), "-")
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ReplaceAll(strings.TrimSpace(k), "/", ".")
		if key == "net.ipv4.ip_forward" ||
			(strings.HasPrefix(key, "net.ipv4.conf.") && strings.HasSuffix(key, ".forwarding")) {
			last = strings.TrimSpace(v)
		}
	}
	return last
}

func probeForwardBoot(_ context.Context, env surroundEnv) []observation {
	f := foreign(factForwardBoot, "Пересылка при загрузке", hostcaps.HowFile)
	files := forwardBootFiles(env.root)
	if len(files) == 0 {
		f.Answer = hostcaps.No
		return seen(f)
	}
	f.Answer, f.Level, f.Support = hostcaps.Yes, hostcaps.LevelError, files
	f.Found = "Настройки системы включают пересылку трафика при загрузке, раньше защиты шлюза: в первые секунды после включения трафик офиса может пройти без защиты. Уберите из настроек системы включение пересылки — шлюз включает её сам, когда защита уже стоит."
	if env.legacyGateway() {
		f.Cause = hostcaps.CauseLegacy
	}
	return seen(f)
}

func probeLegacy(_ context.Context, env surroundEnv) []observation {
	var units legacyvpn.UnitState
	if env.unitsKnown {
		units = func(unit string) (bool, bool) {
			st := env.units(strings.TrimSuffix(unit, ".service"))
			return st.Enabled, st.Active
		}
	}

	r := env.legacyReport(units)
	gw := foreign(factLegacy, "Старый скрипт vpn.sh", hostcaps.HowFile)
	gw.Answer, gw.Cause = hostcaps.No, hostcaps.CauseLegacy
	if r.Gateway {
		gw.Answer, gw.Value, gw.Level, gw.Support = hostcaps.Yes, r.Mode, hostcaps.LevelWarn, r.Support
		gw.Found = "На сервере стоит шлюз старого скрипта vpn.sh"
		if w := legacyvpn.ModeWord(r.Mode); w != "" {
			gw.Found += " (" + w + ")"
		}
		gw.Found += ". Офис работает на нём; ничего не трогайте, пока не будете готовы перейти на панель."
	}
	facts := []hostcaps.Fact{gw}

	dangers := map[string]legacyvpn.Danger{}
	for _, d := range r.Danger {
		dangers[d.ID] = d
	}
	for _, d := range []struct{ id, key, title, text string }{
		{factLegacySudo, "sudo", "Права веб-сервера",
			"Веб-сервер может выполнять любые команды от имени администратора системы: кто попал в старую веб-панель, управляет всем сервером. Не пускайте посторонних к старой веб-панели."},
		{factLegacyRoot, "root_service", "Служба из открытой папки",
			"Служба бота работает от имени администратора системы из папки, в которую может писать любой: подменив файл в папке, можно управлять сервером."},
		{factLegacyTerm, "terminal", "Терминал в браузере",
			"На сервере работает терминал в браузере: через него можно войти в систему из сети офиса. Если он не нужен, выключите его."},
		{factLegacyUSB, "usb", "Автозапуск с флешки",
			"Сервер сам монтирует любую вставленную флешку и может запустить с неё сценарий. Не вставляйте в сервер чужие флешки."},
	} {
		f := foreign(d.id, d.title, hostcaps.HowFile)
		f.Answer = hostcaps.No
		if d.key == "terminal" {
			f.How = hostcaps.HowUnit
			if !env.unitsKnown {

				f.Answer = hostcaps.Unknown
			}
		}
		if got, ok := dangers[d.key]; ok {
			f.Answer, f.Level, f.Found, f.Support = hostcaps.Yes, hostcaps.LevelError, d.text, got.Support
			if got.Attributed {
				f.Cause = hostcaps.CauseLegacy
				f.Found += " Это настройка старого скрипта vpn.sh."
			}
		}
		facts = append(facts, f)
	}

	keys := foreign(factLegacyKeys, "Ключи VPN", hostcaps.HowFile)
	keys.Answer = hostcaps.No
	exposed := exposedKeyFiles(env.root)
	if len(exposed) > 0 {
		keys.Answer, keys.Level, keys.Support = hostcaps.Yes, hostcaps.LevelError, exposed
		keys.Found = "Файлы подключения VPN может прочитать не только система, а любой пользователь сервера. Запросите у поставщика VPN новые ключи и загрузите подключение заново."
		if r.Gateway {
			keys.Cause = hostcaps.CauseLegacy
		}
	}
	facts = append(facts, keys)

	pppoe := foreign(factLegacyPPPoE, "PPPoE старого скрипта", hostcaps.HowFile)
	pppoe.Answer, pppoe.Cause = hostcaps.No, hostcaps.CauseLegacy
	if r.PPPoE {
		pppoe.Answer, pppoe.Level = hostcaps.Yes, hostcaps.LevelError
		pppoe.Found = "Старый скрипт vpn.sh каждую минуту сам поднимает подключение PPPoE. Пока это так, не включайте PPPoE в панели: два подключения мешают друг другу."
	}
	tun := foreign(factLegacyTun, "Канал старого скрипта", hostcaps.HowUnit)
	tun.Answer, tun.Cause = hostcaps.No, hostcaps.CauseLegacy
	switch {
	case r.Tunnel:
		tun.Answer, tun.Level = hostcaps.Yes, hostcaps.LevelError
		tun.Found = "Работает канал VPN старого скрипта vpn.sh. Пока он работает, не включайте VPN в панели: два канала мешают друг другу."
	case !env.unitsKnown:
		tun.Answer = hostcaps.Unknown
	}
	rerun := foreign(factLegacyRerun, "Повторный запуск старого скрипта", hostcaps.HowFile)
	rerun.Answer, rerun.Cause = hostcaps.No, hostcaps.CauseLegacy
	why := r.Rerun

	if r.Gateway && len(exposed) > 0 {
		why = append(why, "panel_keys_changed")
	}
	if len(why) > 0 {
		rerun.Answer, rerun.Level, rerun.Support = hostcaps.Yes, hostcaps.LevelError, why
		rerun.Found = "Старый скрипт vpn.sh запускали после установки панели: он заменил её настройки своими. Не запускайте его поверх панели."
	}
	run := foreign(factLegacyRun, "Старый скрипт работает", hostcaps.HowProcess)
	run.Answer, run.Cause = hostcaps.No, hostcaps.CauseLegacy
	if st, ok := legacyvpn.Running(env.root); ok {
		run.Answer, run.Level, run.Value = hostcaps.Yes, hostcaps.LevelWarn, "waiting"
		run.Found = "Старый скрипт vpn.sh запущен и ждёт ответа в консоли."
		if st.Changing {
			run.Value = "changing"
			run.Found = "Старый скрипт vpn.sh сейчас меняет систему. Дождитесь, пока он закончит, и только потом применяйте настройки в панели."
		}
	}
	return seen(append(facts, pppoe, tun, rerun, run)...)
}

func exposedKeyFiles(root string) []string {
	var out []string
	for _, p := range []string{wgDir + "/" + wgProfilePfx + "*.conf", livePath(),
		ovpnDir + "/" + ovpnProfilePfx + "*.conf", ovpnLivePath()} {
		paths, _ := filepath.Glob(filepath.Join(root, p))
		for _, path := range paths {
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if st.Uid != keyOwner || fi.Mode().Perm()&0o077 != 0 {
				out = append(out, strings.TrimPrefix(path, filepath.Clean(root)))
			}
		}
	}
	sort.Strings(out)
	return out
}

var keyOwner uint32
