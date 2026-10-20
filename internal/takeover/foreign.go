package takeover

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const keaUnit = "kea-dhcp4-server.service"

const (
	unitFirewalld = "firewalld.service"
	unitNftables  = "nftables.service"
	unitUFW       = "ufw.service"
)

var hostUnits = map[string]string{
	"NetworkManager.service":   "NetworkManager",
	"systemd-networkd.service": "встроенная служба сети",
	"libvirtd.service":         "служба виртуальных машин",
	"virtnetworkd.service":     "служба виртуальных машин",
	"virtqemud.service":        "служба виртуальных машин",
	"lxd.service":              "служба контейнеров",
	"snap.lxd.daemon.service":  "служба контейнеров",
	"incus.service":            "служба контейнеров",
	"docker.service":           "Docker",
	"containerd.service":       "Docker",
}

var dhcpNames = map[string]string{
	"isc-dhcp-server.service": "ISC DHCP",
	"dnsmasq.service":         "dnsmasq",
	"udhcpd.service":          "udhcpd",
}

func (b *builder) foreign() {
	b.foreignDHCP()
	b.foreignNetplan()
	b.foreignForward()
	b.foreignSysctl()
	if b.env.Docker {
		b.add(Item{
			ID: "foreign.docker", Kind: KindLocked, Locked: true, Order: orderOther,
			Title: "Docker",
			Found: "На сервере работает Docker. Панель его не трогает: правила и сети Docker остаются как есть.",
		})
	}
	if b.env.VM {
		b.add(Item{
			ID: "foreign.vm", Kind: KindLocked, Locked: true, Order: orderOther,
			Title: "Виртуальные машины",
			Found: "На сервере работают виртуальные машины. Панель их не трогает.",
		})
	}
}

func (b *builder) foreignDHCP() {
	for _, u := range b.env.DHCPUnits {
		if u == keaUnit || (u == unitISC && b.has("legacy.dhcp")) {
			continue
		}
		id := "foreign.dhcp." + shortUnit(u)
		if host, ok := hostUnits[u]; ok {
			b.add(Item{
				ID: id, Kind: KindLocked, Locked: true, Order: orderDHCP,
				Title: "Другая раздача адресов",
				Found: "Адреса в сети офиса раздаёт " + host + ". Панель её не выключает: на ней держится сам сервер. Выключите раздачу адресов на картах офиса в её настройках.",
			})
			b.note(id, u)
			continue
		}
		who := "Ещё одна служба"
		if n, ok := dhcpNames[u]; ok {
			who = "Программа " + n
		}
		b.add(Item{
			ID: id, Kind: KindService, Order: orderDHCP,
			Title: "Другая раздача адресов",
			Found: who + " раздаёт адреса в сети офиса. Панель выключит её: иначе после перезагрузки адреса раздавал бы то один сервер, то другой.",
			Step3: b.retireAll(u, true, true),
		})
	}
}

func (b *builder) foreignNetplan() {
	for _, f := range b.netplanFiles() {
		described, others := f.describes(b.env.PlanCards, b.env.AllCards, b.env.CardMACs)
		if len(described) == 0 {
			continue
		}
		p := legacyvpn.NetplanDir + "/" + f.name
		id := "foreign.netplan." + f.name
		found := "Ещё одни настройки сети описывают " + cardsWord(described) + ". Панель уберёт их в резервную копию, иначе они смешаются с настройками панели. Если сеть не подтвердить, они вернутся."
		if len(others) > 0 {

			stays := " останется"
			if len(others) > 1 {
				stays = " останутся"
			}
			found = "Ещё одни настройки сети описывают " + cardsWord(described) + ", и в них же описано " + listRU(others) + ". Если отметить пункт, панель уберёт эти настройки в резервную копию, и " + listRU(others) + stays + " без настроек. Если не отмечать, они смешаются с настройками панели."
			b.uncheck(id)
		}
		b.add(Item{
			ID: id, Kind: KindNetplan, Order: orderOther,
			Title: "Другие настройки сети",
			Found: found,
			Step1: []Op{{Kind: OpAside, Path: p}},
			Step3: []Op{{Kind: OpBackup, Path: p}},
		})
		b.note(id, described...)
	}
}

func cardsWord(cards []string) string {
	if len(cards) == 1 {
		return "карту " + cards[0]
	}
	return "карты " + strings.Join(cards, ", ")
}

func (b *builder) foreignForward() {
	for _, u := range b.env.ForwardSources {
		switch {
		case u == "docker.service":

			continue
		case u == unitPersistent && b.has("legacy.forward"):
			continue
		}
		it := Item{
			ID: "foreign.forward." + shortUnit(u), Kind: KindFirewall, Order: orderForward,
			Title: "Чужой фаервол",
		}
		const guard = " Защиту офиса держит панель."
		switch u {
		case unitPersistent:

			it.Step3 = append(b.retireAll(u, false, true), b.savedRules()...)
			it.Found = "Система при каждой загрузке восстанавливает сохранённые правила iptables с запретом пересылки трафика. Панель снимет запрет и выключит восстановление, файлы правил уйдут в резервную копию." + guard + b.keptNote()
		case unitFirewalld:

			it.Step3 = b.retireAll(u, true, true)
			it.Found = "Программа firewalld запрещает пересылку трафика. Панель выключит её, и запрет снимется." + guard
		case unitUFW:
			it.Step3 = append(b.retireAll(u, false, false), b.forwardOpen("ip"))
			it.Found = "Программа ufw при каждой загрузке ставит запрет пересылки трафика. Панель выключит её запуск и снимет запрет." + guard + b.keptNote()
		case unitNftables:

			data, _ := b.read("/etc/nftables.conf")
			var chains []Op
			for _, c := range nftForwardChains(data) {
				chains = append(chains, Op{Kind: OpForwardPolicy, Family: c.family, Table: c.table, Chain: c.chain})
			}
			if len(chains) == 0 {
				chains = []Op{{Kind: OpForwardPolicy}}
			}
			it.Step3 = append(b.retireAll(u, false, false), chains...)
			it.Found = "Фаервол nftables при каждой загрузке ставит запрет пересылки трафика. Панель выключит его запуск и сразу снимет общий запрет, а отдельные запреты в его правилах пропадут после перезагрузки." + guard
		default:
			it.Step3 = append(b.retireAll(u, false, false), Op{Kind: OpForwardPolicy})
			it.Found = "Другая программа при каждой загрузке ставит запрет пересылки трафика. Панель выключит её запуск и сразу снимет общий запрет, а отдельные запреты в её правилах пропадут после перезагрузки." + guard
		}
		b.add(it)
	}
}

func (b *builder) foreignSysctl() {
	for _, p := range b.env.ForwardBootFiles {

		if !strings.HasPrefix(p, "/etc/") {
			continue
		}
		if p == legacyvpn.SysctlConf && b.has("legacy.sysctl") {
			continue
		}
		data, ok := b.read(p)
		if !ok {
			continue
		}
		var keys []string
		for _, k := range activeKeys(data) {
			if forwardKey(k) {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			continue
		}
		slices.Sort(keys)
		b.add(Item{
			ID: "foreign.sysctl." + filepath.Base(p), Kind: KindSysctl, Order: orderOther,
			Title: "Пересылка при загрузке",
			Found: "Настройки системы включают пересылку трафика при загрузке, раньше защиты шлюза. Панель отключит эти строки: пересылку она включает сама, когда защита уже стоит.",
			Step3: []Op{{Kind: OpCommentKeys, Path: p, Keys: keys}},
		})
	}
}

type chainRef struct{ family, table, chain string }

var nftFamilies = map[string]bool{"ip": true, "ip6": true, "inet": true, "arp": true, "bridge": true, "netdev": true}

func nftForwardChains(data []byte) []chainRef {
	type frame struct {
		kind         string
		family, name string
	}
	var stack []frame
	var out []chainRef
	var pending *frame
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.NewReplacer("{", " { ", "}", " } ", ";", " ; ").Replace(line)
		tok := strings.Fields(line)
		for i := 0; i < len(tok); i++ {
			t := tok[i]
			switch t {
			case "{":
				f := frame{}
				if pending != nil {
					f, pending = *pending, nil
				}
				stack = append(stack, f)
				continue
			case "}":
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				continue
			case ";":
				continue
			}
			inTable := len(stack) > 0 && stack[len(stack)-1].kind == "table"
			switch {
			case t == "table" && i+1 < len(tok):
				fam, name := "ip", tok[i+1]
				if nftFamilies[name] && i+2 < len(tok) {
					fam, name = name, tok[i+2]
				}
				pending = &frame{kind: "table", family: fam, name: name}
			case t == "chain" && inTable && i+1 < len(tok):
				tbl := stack[len(stack)-1]
				pending = &frame{kind: "chain", family: tbl.family, name: tbl.name + "\x00" + tok[i+1]}
			case t == "chain" && !inTable && i+2 < len(tok):

				fam, rest := "ip", tok[i+1:]
				if nftFamilies[rest[0]] {
					fam, rest = rest[0], rest[1:]
				}
				if len(rest) >= 2 {
					pending = &frame{kind: "chain", family: fam, name: rest[0] + "\x00" + rest[1]}
				}
			case t == "hook" && i+1 < len(tok) && tok[i+1] == "forward":
				for j := len(stack) - 1; j >= 0; j-- {
					if stack[j].kind == "chain" {
						table, chain, _ := strings.Cut(stack[j].name, "\x00")
						c := chainRef{stack[j].family, table, chain}
						if forwardFamilies[c.family] && !slices.Contains(out, c) {
							out = append(out, c)
						}
						break
					}
				}
			}
		}

		pending = nil
	}
	return out
}
