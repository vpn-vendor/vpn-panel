package takeover

import (
	"slices"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const (
	unitApache     = "apache2.service"
	unitISC        = "isc-dhcp-server.service"
	unitCron       = "cron.service"
	unitPersistent = "netfilter-persistent.service"
	unitOpenVPN    = legacyvpn.OpenVPNUnit
	unitMTU        = "vpn_mtu_daemon.service"
)

func waitPPPD() Op {
	return Op{Kind: OpWaitGone, Argv0: "pppd", Args: []string{"call", legacyvpn.PPPoECommand}}
}

const (
	openvpnAutostart = "AUTOSTART"
	autostartNone    = "none"
)

const wireguardMode = 0o700

func (b *builder) legacy() {
	b.legacyNetplan()
	b.legacyTunnel()
	b.legacyPPPoE()
	b.legacyDHCP()
	b.legacyForward()
	b.legacyWeb()
	b.legacyTerminal()
	b.legacyDaemons()
	b.legacySudo()
	b.legacyUSB()
	b.legacySysctl()
	b.legacyScript()
}

func (b *builder) legacyNetplan() {
	p := legacyvpn.ScriptNetplan
	if !b.isFile(p) {
		return
	}
	b.add(Item{
		ID: "legacy.netplan", Kind: KindNetplan, Order: orderOther,
		Title: "Настройки сети старого скрипта",
		Found: "Старый скрипт задаёт картам свои адреса. Панель уберёт эти настройки, иначе у карты офиса будет два адреса. Если сеть не подтвердить, они вернутся.",
		Step1: []Op{{Kind: OpAside, Path: p}},
		Step3: []Op{{Kind: OpBackup, Path: p}},
	})
}

func (b *builder) legacyTunnel() {
	var units, confs []string
	for _, t := range legacyvpn.Tunnels() {
		have := b.isFile(t.Conf)
		if have {
			confs = append(confs, t.Conf)
		}
		if have || b.present(t.Unit) {
			units = append(units, t.Unit)
		}
	}
	if len(units) == 0 {
		return
	}

	if b.isFile(legacyvpn.OpenVPNDefault) || b.present(unitOpenVPN) {
		units = append(units, unitOpenVPN)
	}
	it := Item{
		ID: "legacy.tunnel", Kind: KindService, Order: orderOther,
		Title: "Канал VPN старого скрипта",
		Found: "Канал VPN старого скрипта остановится на время проверки сети, а после подтверждения выключится насовсем. Его файл подключения уйдёт в резервную копию.",
	}
	var r retirement
	for _, u := range units {
		b.retire(&r, u, true, true)
		if !b.env.UnitsKnown {
			continue
		}
		it.Step1 = append(it.Step1, Op{Kind: OpStop, Unit: u})
		if b.st(u).Active {
			it.Undo = append(it.Undo, Op{Kind: OpStart, Unit: u})
		}
	}
	it.Step3 = r.list()
	for _, c := range confs {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: c})
	}
	if len(confs) == 0 {
		it.Found = "Канал VPN старого скрипта остановится на время проверки сети, а после подтверждения выключится насовсем."
	}
	if data, ok := b.read(legacyvpn.OpenVPNDefault); ok {

		if v, _ := shellValue(data, openvpnAutostart); v != autostartNone {
			it.Step3 = append(it.Step3, Op{Kind: OpSetKey, Path: legacyvpn.OpenVPNDefault, Key: openvpnAutostart, Value: autostartNone})
		}
	}

	dirs := false
	if b.isDir(legacyvpn.OpenVPNDir) {
		it.Step3 = append(it.Step3, Op{Kind: OpChownRoot, Path: legacyvpn.OpenVPNDir})
		dirs = true
	}
	if b.isDir(legacyvpn.WireGuardDir) {
		it.Step3 = append(it.Step3, Op{Kind: OpChownRoot, Path: legacyvpn.WireGuardDir, Mode: wireguardMode})
		dirs = true
	}
	if dirs {
		it.Found += " Веб-сервер старой панели больше не сможет менять файлы каналов VPN."
	}
	b.add(it)
}

func (b *builder) legacyPPPoE() {
	data, _ := b.read(legacyvpn.Crontab)
	lines := legacyvpn.PPPoECronLines(data)
	if len(lines) == 0 {
		return
	}
	slices.Sort(lines)
	poff := []Op{{Kind: OpExec, Command: CmdPoff}, waitPPPD()}
	it := Item{
		ID: "legacy.pppoe", Kind: KindCron, Order: orderOther,
		Title: "PPPoE старого скрипта",
		Found: "Подключение PPPoE старого скрипта остановится, и скрипт перестанет поднимать его каждую минуту. Пока подключение переходит к панели, интернет ненадолго пропадёт.",
	}

	if b.env.UnitsKnown {
		it.Step1 = append([]Op{{Kind: OpStop, Unit: unitCron}}, poff...)

		it.Undo = append(it.Undo, Op{Kind: OpExec, Command: CmdPon})
		if b.st(unitCron).Active {
			it.Undo = append(it.Undo, Op{Kind: OpStart, Unit: unitCron})
		}
	}

	it.Step3 = []Op{{Kind: OpStop, Unit: unitCron}, {Kind: OpDropLines, Path: legacyvpn.Crontab, Lines: lines}}
	it.Step3 = append(it.Step3, poff...)
	if b.isFile(legacyvpn.PPPoEPeer) {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: legacyvpn.PPPoEPeer})
	}
	if !b.env.UnitsKnown || b.st(unitCron).Enabled {
		it.Step3 = append(it.Step3, Op{Kind: OpStart, Unit: unitCron})
	}
	b.add(it)
}

func (b *builder) legacyDHCP() {
	if !slices.Contains(b.env.DHCPUnits, unitISC) && !b.present(unitISC) {
		return
	}
	b.add(Item{
		ID: "legacy.dhcp", Kind: KindService, Order: orderDHCP,
		Title: "Раздача адресов старого скрипта",
		Found: "ISC DHCP старого скрипта выключится, адреса офису начнёт раздавать панель.",
		Step3: b.retireAll(unitISC, true, true),
	})
}

func (b *builder) legacyForward() {
	rules := b.isFile(legacyvpn.RulesV4)
	persistent := b.present(unitPersistent)
	if !rules && !persistent {
		return
	}
	it := Item{
		ID: "legacy.forward", Kind: KindFirewall, Order: orderForward,
		Title: "Фаервол старого скрипта",
		Found: "Старые правила фаервола запрещают пересылку трафика и возвращаются при каждой загрузке. Панель снимет запрет и выключит их восстановление, файлы правил уйдут в резервную копию. Защиту офиса держит панель." + b.keptNote(),
	}

	if b.marker(daemon("vpn_mtu_daemon").Marker) || b.present(unitMTU) {
		it.Step3 = append(it.Step3, Op{Kind: OpStop, Unit: unitMTU})
	}

	if persistent || (rules && !b.env.UnitsKnown) {
		it.Step3 = append(it.Step3, b.retireAll(unitPersistent, false, true)...)
	}
	it.Step3 = append(it.Step3, b.savedRules()...)
	b.add(it)
}

func (b *builder) savedRules() []Op {
	var ops []Op
	for _, p := range []string{legacyvpn.RulesV4, legacyvpn.RulesV6} {
		if b.isFile(p) {
			ops = append(ops, Op{Kind: OpBackup, Path: p})
		}
	}
	ops = append(ops, b.forwardOpen("ip"))
	if data, ok := b.read(legacyvpn.RulesV6); ok && savedForwardBlocked(data) {
		ops = append(ops, b.forwardOpen("ip6"))
	}
	return ops
}

func (b *builder) forwardOpen(family string) Op {
	op := Op{Kind: OpForwardAccept, Family: family, Table: "filter", Chain: "FORWARD"}
	if b.env.Docker || b.env.VM {
		op.Kind = OpForwardPrune
	}
	return op
}

func (b *builder) keptNote() string {
	switch {
	case b.env.Docker && b.env.VM:
		return " Правила Docker и виртуальных машин останутся как есть."
	case b.env.Docker:
		return " Правила Docker останутся как есть."
	case b.env.VM:
		return " Правила виртуальных машин останутся как есть."
	}
	return ""
}

func savedForwardBlocked(data []byte) bool {
	filter := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case strings.HasPrefix(f[0], "*"):
			filter = f[0] == "*filter"
		case !filter:
		case f[0] == ":FORWARD":
			if len(f) >= 2 && f[1] == "DROP" {
				return true
			}
		case len(f) >= 2 && f[0] == "-A" && f[1] == "FORWARD":
			for i := 2; i+1 < len(f); i++ {
				if (f[i] == "-j" || f[i] == "--jump") && (f[i+1] == "DROP" || f[i+1] == "REJECT") {
					return true
				}
			}
		}
	}
	return false
}

func (b *builder) legacyWeb() {
	if !b.present(unitApache) {
		return
	}
	b.add(Item{
		ID: "legacy.web", Kind: KindService, Order: orderOther,
		Title: "Старая веб-панель",
		Found: "Apache со старой веб-панелью выключится: старая панель перестанет открываться. Её файлы останутся на месте.",
		Step3: b.retireAll(unitApache, true, false),
	})
}

func (b *builder) legacyTerminal() {
	u := legacyvpn.TerminalUnit
	if !b.present(u) {
		return
	}
	b.add(Item{
		ID: "legacy.terminal", Kind: KindService, Order: orderOther,
		Title: "Терминал в браузере",
		Found: "Терминал сервера в браузере выключится. Вход по SSH это не затрагивает.",
		Step3: b.retireAll(u, true, true),
	})
}

var daemonWords = map[string]string{
	"ping_daemon":         "проверка связи",
	"vpn_mtu_daemon":      "подстройка канала VPN",
	"telegram_bot":        "бот Telegram",
	"update_metrics":      "сбор графиков старой панели",
	"network_load":        "сбор графиков старой панели",
	"home_metrics_daemon": "сбор графиков старой панели",
}

func daemon(name string) legacyvpn.Daemon {
	for _, d := range legacyvpn.Daemons() {
		if d.Name == name {
			return d
		}
	}
	return legacyvpn.Daemon{}
}

func (b *builder) legacyDaemons() {
	it := Item{ID: "legacy.daemons", Kind: KindService, Order: orderOther, Title: "Службы старого скрипта"}
	var words []string
	var r retirement
	var scripts []string
	for _, d := range legacyvpn.Daemons() {
		if b.marker(d.Marker) {
			b.retire(&r, d.Unit, true, true)
			if w := daemonWords[d.Name]; !slices.Contains(words, w) {
				words = append(words, w)
			}
		}
		if d.Script != "" && b.marker(d.ScriptMarker) {
			scripts = append(scripts, d.Script)
		}
	}
	if len(r.ops) == 0 && len(scripts) == 0 {
		return
	}
	it.Step3 = r.list()
	for _, s := range scripts {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: s})
	}
	if b.isFile(legacyvpn.WebCrontab) {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: legacyvpn.WebCrontab})
		if !slices.Contains(words, daemonWords["update_metrics"]) {
			words = append(words, daemonWords["update_metrics"])
		}
	}
	it.Found = "Выключатся " + listRU(words) + ". Их файлы уйдут в резервную копию."
	if len(words) == 0 {
		it.Found = "Файлы служб старого скрипта уйдут в резервную копию."
	}
	b.add(it)
}

func (b *builder) legacySudo() {
	data, _ := b.read(legacyvpn.Sudoers)
	var lines []string
	for _, l := range legacyvpn.SudoersLines() {
		if hasTrimmedLine(data, l) {
			lines = append(lines, l)
		}
	}
	it := Item{
		ID: "legacy.sudo", Kind: KindSudoers, Order: orderOther,
		Title: "Права веб-сервера",
		Found: "Веб-сервер старой панели может выполнять команды от имени администратора системы. Панель отберёт у него эти права.",
	}
	if len(lines) > 0 {
		slices.Sort(lines)
		it.Step3 = append(it.Step3, Op{Kind: OpSudoers, Path: legacyvpn.Sudoers, Lines: lines})
	}
	if b.isFile(legacyvpn.BotSudoers) {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: legacyvpn.BotSudoers})
	}
	if len(it.Step3) > 0 {
		b.add(it)
	}
}

func (b *builder) legacyUSB() {
	it := Item{
		ID: "legacy.usb", Kind: KindFile, Order: orderUSB,
		Title: "Автозапуск с флешки",
		Found: "Сервер перестанет сам монтировать флешки и запускать с них старый скрипт.",
	}
	rule := b.marker(legacyvpn.MarkerUdevRule)
	if rule {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: legacyvpn.UdevRule})
	}
	if b.marker(legacyvpn.MarkerMountUSB) {
		it.Step3 = append(it.Step3, Op{Kind: OpBackup, Path: legacyvpn.MountUSB})
	}
	if len(it.Step3) == 0 {
		return
	}
	if rule {
		it.Step3 = append(it.Step3, Op{Kind: OpExec, Command: CmdUdevReload})
	}
	b.add(it)
}

func (b *builder) legacySysctl() {
	data, _ := b.read(legacyvpn.SysctlConf)
	var keys []string
	fwd, timeout := false, false
	for _, k := range activeKeys(data) {
		switch {
		case forwardKey(k):

			keys, fwd = append(keys, k), true
		case slices.Contains(legacyvpn.SysctlKeys(), k):
			keys, timeout = append(keys, k), true
		}
	}
	if len(keys) == 0 {
		return
	}
	slices.Sort(keys)
	var text []string
	if fwd {
		text = append(text, "Старый скрипт включает пересылку трафика при загрузке, раньше защиты шлюза.")
	}
	if timeout {
		text = append(text, "Он меняет, сколько ядро помнит соединения UDP, и это спорит с настройками телефонии панели.")
	}
	text = append(text, "Панель отключит эти строки.")
	if fwd {
		text = append(text, "Пересылку она включает сама, когда защита уже стоит.")
	}
	b.add(Item{
		ID: "legacy.sysctl", Kind: KindSysctl, Order: orderOther,
		Title: "Настройки ядра старого скрипта",
		Found: strings.Join(text, " "),
		Step3: []Op{{Kind: OpCommentKeys, Path: legacyvpn.SysctlConf, Keys: keys}},
	})
}

func (b *builder) legacyScript() {
	if len(b.env.HomeScripts) == 0 {
		return
	}
	it := Item{
		ID: "legacy.script", Kind: KindScript, Order: orderScript,
		Title: "Сам старый скрипт",
		Found: "Старый скрипт уйдёт в резервную копию, на его месте останется заглушка: его запуск больше ничего не поменяет на сервере.",
	}
	for _, p := range b.env.HomeScripts {
		it.Step3 = append(it.Step3, Op{Kind: OpStub, Path: p})
	}
	b.add(it)
}
