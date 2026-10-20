package nftforeign

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var (
	ownTables = []string{"inet vpn_panel", "inet vpn_panel_dhcp"}
	lan       = []string{"ens3"}
	viaVPN    = []string{"wg-vpn0"}
	direct    = []string{"ens2"}
)

const (
	meta102 = `{"metainfo": {"version": "1.0.2", "json_schema_version": 1}}`
	meta116 = `{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}`

	xtNull      = `{"xt": null}`
	xtState116  = `{"xt": {"type": "match", "name": "conntrack"}}`
	xtReject116 = `{"xt": {"type": "target", "name": "REJECT"}}`

	counter = `{"counter": {"packets": 0, "bytes": 0}}`
	accept  = `{"accept": null}`
	drop    = `{"drop": null}`
	reject  = `{"reject": null}`
	ret     = `{"return": null}`
)

func doc(meta string, items ...string) []byte {
	return []byte(`{"nftables": [` + strings.Join(append([]string{meta}, items...), ", ") + `]}`)
}

func tableJSON(family, name string) string {
	return fmt.Sprintf(`{"table": {"family": %q, "name": %q, "handle": 1}}`, family, name)
}

func chainJSON(family, tbl, name, hook, policy string) string {
	if hook == "" {
		return fmt.Sprintf(`{"chain": {"family": %q, "table": %q, "name": %q, "handle": 1}}`, family, tbl, name)
	}
	return fmt.Sprintf(`{"chain": {"family": %q, "table": %q, "name": %q, "handle": 1, "type": "filter", "hook": %q, "prio": 0, "policy": %q}}`,
		family, tbl, name, hook, policy)
}

func ruleJSON(family, tbl, ch string, expr ...string) string {
	return fmt.Sprintf(`{"rule": {"family": %q, "table": %q, "chain": %q, "handle": 2, "expr": [%s]}}`,
		family, tbl, ch, strings.Join(expr, ", "))
}

func ifMatch(key, op, right string) string {
	return fmt.Sprintf(`{"match": {"op": %q, "left": {"meta": {"key": %q}}, "right": %s}}`, op, key, right)
}

func iif(name string) string { return ifMatch("iifname", "==", fmt.Sprintf("%q", name)) }
func oif(name string) string { return ifMatch("oifname", "==", fmt.Sprintf("%q", name)) }
func jump(to string) string  { return fmt.Sprintf(`{"jump": {"target": %q}}`, to) }

func oldScript(policy, xtState, xtReject string) []string {
	return []string{
		tableJSON("ip", "filter"),
		chainJSON("ip", "filter", "INPUT", "input", "accept"),
		chainJSON("ip", "filter", "FORWARD", "forward", policy),
		chainJSON("ip", "filter", "OUTPUT", "output", "accept"),
		ruleJSON("ip", "filter", "FORWARD", iif("ens3"), oif("tun0"), counter, accept),
		ruleJSON("ip", "filter", "FORWARD", iif("tun0"), oif("ens3"), xtState, counter, accept),
		ruleJSON("ip", "filter", "FORWARD", iif("ens3"), oif("ens3"), counter, accept),
		ruleJSON("ip", "filter", "FORWARD", iif("ens3"), oif("ens2"), counter, xtReject),
	}
}

func emptyFilter(family string) []string {
	return []string{
		tableJSON(family, "filter"),
		chainJSON(family, "filter", "INPUT", "input", "accept"),
		chainJSON(family, "filter", "FORWARD", "forward", "accept"),
		chainJSON(family, "filter", "OUTPUT", "output", "accept"),
	}
}

var panelTables = []string{
	tableJSON("inet", "vpn_panel"),
	`{"counter": {"family": "inet", "name": "seen_early", "table": "vpn_panel", "handle": 30, "packets": 12, "bytes": 720}}`,
	chainJSON("inet", "vpn_panel", "forward", "forward", "drop"),
	`{"chain": {"family": "inet", "table": "vpn_panel", "name": "witness_early", "handle": 31, "type": "filter", "hook": "forward", "prio": -310, "policy": "accept"}}`,
	ruleJSON("inet", "vpn_panel", "forward", ifMatch("nfproto", "==", `"ipv6"`), drop),
	ruleJSON("inet", "vpn_panel", "forward", ifMatch("iifname", "==", `{"set": ["ens3"]}`),
		`{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 3544}}`, drop),
	ruleJSON("inet", "vpn_panel", "forward", ifMatch("iifname", "==", `{"set": ["ens3"]}`), oif("wg-vpn0"), accept),
	ruleJSON("inet", "vpn_panel", "witness_early", ifMatch("iifname", "==", `{"set": ["ens3"]}`), oif("wg-vpn0"),
		`{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}}`, `{"counter": "seen_early"}`, ret),
	tableJSON("inet", "vpn_panel_dhcp"),
	`{"chain": {"family": "inet", "table": "vpn_panel_dhcp", "name": "watch", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -150, "policy": "accept"}}`,
}

var dockerTables = []string{
	tableJSON("ip", "filter"),
	chainJSON("ip", "filter", "FORWARD", "forward", "drop"),
	chainJSON("ip", "filter", "DOCKER", "", ""),
	chainJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-1", "", ""),
	chainJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-2", "", ""),
	chainJSON("ip", "filter", "DOCKER-USER", "", ""),
	ruleJSON("ip", "filter", "FORWARD", counter, jump("DOCKER-USER")),
	ruleJSON("ip", "filter", "FORWARD", counter, jump("DOCKER-ISOLATION-STAGE-1")),
	ruleJSON("ip", "filter", "FORWARD", oif("docker0"),
		`{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}`, counter, accept),
	ruleJSON("ip", "filter", "FORWARD", oif("docker0"), counter, jump("DOCKER")),
	ruleJSON("ip", "filter", "FORWARD", iif("docker0"), ifMatch("oifname", "!=", `"docker0"`), counter, accept),
	ruleJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-1", iif("docker0"), ifMatch("oifname", "!=", `"docker0"`), counter, jump("DOCKER-ISOLATION-STAGE-2")),
	ruleJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-1", counter, ret),
	ruleJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-2", oif("docker0"), counter, drop),
	ruleJSON("ip", "filter", "DOCKER-ISOLATION-STAGE-2", counter, ret),
	ruleJSON("ip", "filter", "DOCKER-USER", counter, ret),
}

var firewalldTables = []string{
	tableJSON("inet", "firewalld"),
	chainJSON("inet", "firewalld", "filter_FORWARD", "forward", "accept"),
	chainJSON("inet", "firewalld", "filter_FORWARD_ZONES", "", ""),
	chainJSON("inet", "firewalld", "filter_FWD_public", "", ""),
	ruleJSON("inet", "firewalld", "filter_FORWARD",
		`{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}`, accept),
	ruleJSON("inet", "firewalld", "filter_FORWARD", iif("lo"), accept),
	ruleJSON("inet", "firewalld", "filter_FORWARD",
		`{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "right": {"set": [{"prefix": {"addr": "::", "len": 96}}]}}}`,
		`{"reject": {"type": "icmpv6", "expr": "addr-unreachable"}}`),
	ruleJSON("inet", "firewalld", "filter_FORWARD", jump("filter_FORWARD_ZONES")),
	ruleJSON("inet", "firewalld", "filter_FORWARD",
		`{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}`, drop),
	ruleJSON("inet", "firewalld", "filter_FORWARD", `{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}`),
	ruleJSON("inet", "firewalld", "filter_FORWARD_ZONES", `{"goto": {"target": "filter_FWD_public"}}`),
}

func items(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestAnalyzeStand(t *testing.T) {
	ipFilter := func(policy string, drops, opaque bool) Verdict {
		return Verdict{Culprits: []Culprit{{Family: "ip", Table: "filter", Policy: policy, Drops: drops, Opaque: opaque}}, Opaque: opaque}
	}
	cases := []struct {
		name         string
		meta         string
		items        []string
		own          []string
		lans, exits  []string
		want         Verdict
		wantCulprits []string
	}{
		{
			name:  "22.04: старый скрипт, панель в режиме VPN — режет политика",
			meta:  meta102,
			items: items(oldScript("drop", xtNull, xtNull), emptyFilter("ip6"), panelTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: ipFilter("drop", false, false),
		},
		{
			name:  "22.04: прямой выход панели — REJECT не назван",
			meta:  meta102,
			items: items(oldScript("drop", xtNull, xtNull), panelTables),
			own:   ownTables, lans: lan, exits: direct,
			want: ipFilter("drop", false, true),
		},
		{
			name:  "22.04 после ufw disable, режим VPN — REJECT только к провайдеру",
			meta:  meta102,
			items: items(oldScript("accept", xtNull, xtNull), emptyFilter("ip6"), panelTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: Verdict{},
		},
		{
			name:  "22.04 после ufw disable, прямой выход — остался нераскрытый REJECT",
			meta:  meta102,
			items: items(oldScript("accept", xtNull, xtNull), emptyFilter("ip6"), panelTables),
			own:   ownTables, lans: lan, exits: direct,
			want: ipFilter("accept", false, true),
		},
		{
			name:  "26.04: REJECT назван, прямой выход",
			meta:  meta116,
			items: items(oldScript("accept", xtState116, xtReject116), panelTables),
			own:   ownTables, lans: lan, exits: direct,
			want: ipFilter("accept", true, false),
		},
		{
			name:  "26.04: REJECT назван, режим VPN",
			meta:  meta116,
			items: items(oldScript("accept", xtState116, xtReject116), panelTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: Verdict{},
		},
		{
			name:  "26.04: политика drop",
			meta:  meta116,
			items: items(oldScript("drop", xtState116, xtReject116), panelTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: ipFilter("drop", false, false),
		},
		{
			name:  "только наша таблица и пустые чужие — виновников нет",
			meta:  meta102,
			items: items(panelTables, emptyFilter("ip"), emptyFilter("ip6")),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: Verdict{},
		},
		{
			name:  "отрицательный контроль: без описи своих наша таблица — виновник",
			meta:  meta102,
			items: items(panelTables, emptyFilter("ip"), emptyFilter("ip6")),
			own:   nil, lans: lan, exits: viaVPN,
			want: Verdict{Culprits: []Culprit{{Family: "inet", Table: "vpn_panel", Policy: "drop", Drops: true}}},
		},
		{
			name: "ip6 с политикой drop не в счёт",
			meta: meta116,
			items: []string{
				tableJSON("ip6", "filter"),
				chainJSON("ip6", "filter", "FORWARD", "forward", "drop"),
				ruleJSON("ip6", "filter", "FORWARD", drop),
			},
			own: ownTables, lans: lan, exits: viaVPN,
			want: Verdict{},
		},
		{
			name:  "Docker через iptables-nft",
			meta:  meta116,
			items: items(dockerTables, panelTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want:         Verdict{Culprits: []Culprit{{Family: "ip", Table: "filter", Policy: "drop", Docker: true}}},
			wantCulprits: []string{"Docker"},
		},
		{
			name:  "firewalld и старый скрипт, порядок по семейству и имени",
			meta:  meta116,
			items: items(oldScript("drop", xtState116, xtReject116), firewalldTables),
			own:   ownTables, lans: lan, exits: viaVPN,
			want: Verdict{Culprits: []Culprit{
				{Family: "inet", Table: "firewalld", Policy: "accept", Drops: true},
				{Family: "ip", Table: "filter", Policy: "drop"},
			}},
			wantCulprits: []string{"firewalld", "правила старого фаервола (iptables)"},
		},
		{
			name: "две цепочки forward в одной таблице — один виновник с drop",
			meta: meta116,
			items: []string{
				tableJSON("inet", "custom"),
				chainJSON("inet", "custom", "fwd_a", "forward", "accept"),
				chainJSON("inet", "custom", "fwd_b", "forward", "drop"),
			},
			own: ownTables, lans: lan, exits: viaVPN,
			want: Verdict{Culprits: []Culprit{{Family: "inet", Table: "custom", Policy: "drop"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Analyze(doc(tc.meta, tc.items...), tc.own, tc.lans, tc.exits)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Analyze:\n got %+v\nwant %+v", got, tc.want)
			}
			if tc.wantCulprits != nil {
				var names []string
				for _, c := range got.Culprits {
					names = append(names, Name(c))
				}
				if !reflect.DeepEqual(names, tc.wantCulprits) {
					t.Fatalf("Name: got %q, want %q", names, tc.wantCulprits)
				}
			}
		})
	}
}

func TestAnalyzeRules(t *testing.T) {
	type sub struct {
		name  string
		rules [][]string
	}
	vmap := func(data string) string {
		return `{"vmap": {"key": {"meta": {"key": "iifname"}}, "data": ` + data + `}}`
	}
	cases := []struct {
		name          string
		rules         [][]string
		subs          []sub
		lans, exits   []string
		drops, opaque bool
	}{
		{name: "drop без условий", rules: [][]string{{drop}}, drops: true},
		{name: "reject", rules: [][]string{{reject}}, drops: true},
		{name: "queue", rules: [][]string{{`{"queue": {"num": 0}}`}}, drops: true},
		{name: "счётчики и журнал — не вердикт", rules: [][]string{{counter, `{"log": {"prefix": "fw "}}`, `{"limit": {"rate": 5, "per": "second"}}`}}},
		{name: "drop только на чужой карте", rules: [][]string{{iif("docker0"), drop}}},
		{name: "маска чужих карт", rules: [][]string{{iif("docker*"), drop}}},
		{name: "маска, подходящая офису", rules: [][]string{{iif("ens*"), drop}}, drops: true},
		{name: "отрицание задевает ответы в офис", rules: [][]string{{ifMatch("iifname", "!=", `"ens3"`), drop}}, drops: true},
		{name: "отрицание исключает выход офиса", rules: [][]string{{iif("ens3"), ifMatch("oifname", "!=", `"wg-vpn0"`), drop}}},
		{name: "канал → канал офис не задевает", rules: [][]string{{iif("wg-vpn0"), oif("wg-vpn0"), drop}}},
		{name: "ответ из канала в офис", rules: [][]string{{iif("wg-vpn0"), oif("ens3"), drop}}, drops: true},
		{name: "набор с выходом офиса", rules: [][]string{{ifMatch("oifname", "==", `{"set": ["ens2", "wg-vpn0"]}`), drop}}, drops: true},
		{name: "набор чужих карт", rules: [][]string{{ifMatch("oifname", "==", `{"set": ["ens2", "docker0"]}`), drop}}},
		{name: "именованный набор офис не исключает", rules: [][]string{{ifMatch("iifname", "==", `"@trusted"`), drop}}, drops: true},
		{name: "только IPv6 по nfproto", rules: [][]string{{ifMatch("nfproto", "==", `"ipv6"`), drop}}},
		{name: "отрицательный контроль: nfproto != ipv6", rules: [][]string{{ifMatch("nfproto", "!=", `"ipv6"`), drop}}, drops: true},
		{name: "поле заголовка IPv6", rules: [][]string{{`{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": {"prefix": {"addr": "fe80::", "len": 10}}}}`, reject}}},
		{name: "jump в цепочку с drop", rules: [][]string{{jump("c")}}, subs: []sub{{"c", [][]string{{drop}}}}, drops: true},
		{name: "jump только с чужой карты", rules: [][]string{{iif("docker0"), jump("c")}}, subs: []sub{{"c", [][]string{{drop}}}}},
		{
			name:  "условие перехода сужает пути внутри",
			rules: [][]string{{iif("ens3"), jump("c")}},
			subs:  []sub{{"c", [][]string{{iif("wg-vpn0"), drop}}}},
		},
		{name: "goto", rules: [][]string{{`{"goto": {"target": "c"}}`}}, subs: []sub{{"c", [][]string{{reject}}}}, drops: true},
		{
			name:  "петля переходов без drop",
			rules: [][]string{{jump("a")}},
			subs:  []sub{{"a", [][]string{{jump("b")}}}, {"b", [][]string{{jump("a")}, {accept}}}},
		},
		{
			name:  "петля переходов с drop",
			rules: [][]string{{jump("a")}},
			subs:  []sub{{"a", [][]string{{jump("b")}}}, {"b", [][]string{{jump("a")}, {drop}}}},
			drops: true,
		},
		{name: "return в базовой цепочке — как политика", rules: [][]string{{iif("ens3"), ret}, {counter, accept}}},
		{name: "переход в цепочку, которой нет", rules: [][]string{{jump("missing")}}, opaque: true},
		{name: "xt: незнакомая цель", rules: [][]string{{`{"xt": {"type": "target", "name": "FOO"}}`}}, opaque: true},
		{name: "xt: LOG без вердикта", rules: [][]string{{`{"xt": {"type": "target", "name": "LOG"}}`}}},
		{name: "xt: незнакомое условие и drop", rules: [][]string{{`{"xt": {"type": "match", "name": "physdev"}}`, drop}}, drops: true},
		{name: "xt без имени при своём accept — условие", rules: [][]string{{xtNull, counter, accept}}},
		{name: "xt без имени без вердикта", rules: [][]string{{counter, xtNull}}, opaque: true},
		{name: "xt без имени на чужих картах", rules: [][]string{{iif("docker0"), xtNull}}},
		{name: "карта вердиктов с drop", rules: [][]string{{vmap(`{"set": [["ens3", {"accept": null}], ["ens9", {"drop": null}]]}`)}}, drops: true},
		{
			name:  "карта вердиктов с переходом",
			rules: [][]string{{vmap(`{"set": [["ens3", {"jump": {"target": "c"}}]]}`)}},
			subs:  []sub{{"c", [][]string{{drop}}}},
			drops: true,
		},
		{name: "именованная карта вердиктов", rules: [][]string{{vmap(`"@fwd_jumps"`)}}, opaque: true},
		{name: "непонятное выражение", rules: [][]string{{`[]`, drop}}, drops: true, opaque: true},
		{name: "карты офиса неизвестны", rules: [][]string{{iif("ens3"), drop}}, lans: []string{}, exits: []string{}, drops: true},
		{name: "отрицательный контроль: офис на другой карте", rules: [][]string{{iif("ens3"), drop}}, lans: []string{"ens4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			its := []string{tableJSON("inet", "custom"), chainJSON("inet", "custom", "forward", "forward", "accept")}
			for _, s := range tc.subs {
				its = append(its, chainJSON("inet", "custom", s.name, "", ""))
			}
			for _, r := range tc.rules {
				its = append(its, ruleJSON("inet", "custom", "forward", r...))
			}
			for _, s := range tc.subs {
				for _, r := range s.rules {
					its = append(its, ruleJSON("inet", "custom", s.name, r...))
				}
			}
			lans, exits := lan, viaVPN
			if tc.lans != nil {
				lans = tc.lans
			}
			if tc.exits != nil {
				exits = tc.exits
			}
			got, err := Analyze(doc(meta116, its...), ownTables, lans, exits)
			if err != nil {
				t.Fatal(err)
			}
			want := Verdict{Opaque: tc.opaque}
			if tc.drops || tc.opaque {
				want.Culprits = []Culprit{{Family: "inet", Table: "custom", Policy: "accept", Drops: tc.drops, Opaque: tc.opaque}}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func fwdChain(name, policy, prio string) string {
	if prio == "" {
		return fmt.Sprintf(`{"chain": {"family": "inet", "table": "custom", "name": %q, "handle": 1, "type": "filter", "hook": "forward", "policy": %q}}`, name, policy)
	}
	return fmt.Sprintf(`{"chain": {"family": "inet", "table": "custom", "name": %q, "handle": 1, "type": "filter", "hook": "forward", "prio": %s, "policy": %q}}`,
		name, prio, policy)
}

func TestOutsideWitness(t *testing.T) {
	culprit := func(policy string, drops, outside bool) Verdict {
		return Verdict{Culprits: []Culprit{{Family: "inet", Table: "custom", Policy: policy, Drops: drops, OutsideWitness: outside}}}
	}
	cases := []struct {
		name  string
		items []string
		want  Verdict
	}{
		{name: "priority 100, политика drop", items: []string{fwdChain("fwd", "drop", "100")}, want: culprit("drop", false, true)},
		{name: "отрицательный контроль: priority 0", items: []string{fwdChain("fwd", "drop", "0")}, want: culprit("drop", false, false)},
		{name: "раньше раннего свидетеля, drop правилом",
			items: []string{fwdChain("fwd", "accept", "-320"), ruleJSON("inet", "custom", "fwd", drop)}, want: culprit("accept", true, true)},
		{name: "граница раннего свидетеля", items: []string{fwdChain("fwd", "drop", "-310")}, want: culprit("drop", false, true)},
		{name: "граница позднего свидетеля", items: []string{fwdChain("fwd", "drop", "60")}, want: culprit("drop", false, true)},
		{name: "сразу за ранним свидетелем", items: []string{fwdChain("fwd", "drop", "-309")}, want: culprit("drop", false, false)},
		{name: "сразу перед поздним свидетелем", items: []string{fwdChain("fwd", "drop", "59")}, want: culprit("drop", false, false)},
		{name: "строкой filter + 10", items: []string{fwdChain("fwd", "drop", `"filter + 10"`)}, want: culprit("drop", false, false)},
		{name: "строкой mangle", items: []string{fwdChain("fwd", "drop", `"mangle"`)}, want: culprit("drop", false, false)},
		{name: "строкой filter + 100", items: []string{fwdChain("fwd", "drop", `"filter + 100"`)}, want: culprit("drop", false, true)},
		{name: "строкой raw - 20", items: []string{fwdChain("fwd", "drop", `"raw - 20"`)}, want: culprit("drop", false, true)},
		{name: "мусор строкой", items: []string{fwdChain("fwd", "drop", `"bogus"`)}, want: culprit("drop", false, true)},
		{name: "дробное число", items: []string{fwdChain("fwd", "drop", "1.5")}, want: culprit("drop", false, true)},
		{name: "null", items: []string{fwdChain("fwd", "drop", "null")}, want: culprit("drop", false, true)},
		{name: "приоритета нет", items: []string{fwdChain("fwd", "drop", "")}, want: culprit("drop", false, true)},
		{name: "вне окна, accept и пусто — не виновник", items: []string{fwdChain("fwd", "accept", "100")}, want: Verdict{}},
		{name: "вне окна, drop только на чужой карте — не виновник",
			items: []string{fwdChain("fwd", "accept", "100"), ruleJSON("inet", "custom", "fwd", iif("docker0"), drop)}, want: Verdict{}},
		{name: "безобидная цепочка вне окна при режущей внутри",
			items: []string{fwdChain("fwd_in", "drop", "0"), fwdChain("fwd_out", "accept", "100")}, want: culprit("drop", false, false)},
		{name: "отрицательный контроль: цепочка вне окна режет",
			items: []string{fwdChain("fwd_in", "drop", "0"), fwdChain("fwd_out", "accept", "100"), ruleJSON("inet", "custom", "fwd_out", drop)},
			want:  culprit("drop", true, true)},
		{name: "не forward — не в счёт",
			items: []string{`{"chain": {"family": "inet", "table": "custom", "name": "pre", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -400, "policy": "drop"}}`},
			want:  Verdict{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Analyze(doc(meta116, append([]string{tableJSON("inet", "custom")}, tc.items...)...), ownTables, lan, viaVPN)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestOwnWitnessesInsideWindow(t *testing.T) {
	got, err := Analyze(doc(meta102, panelTables...), nil, lan, viaVPN)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Culprits) != 1 || got.Culprits[0].OutsideWitness {
		t.Fatalf("got %+v", got)
	}
}

func TestAnalyzeErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		own  []string
		err  bool
	}{
		{name: "не JSON", in: `nft: command not found`, err: true},
		{name: "нет списка nftables", in: `{}`, err: true},
		{name: "элемент не объект", in: `{"nftables": ["x"]}`, err: true},
		{name: "политика не строкой", in: `{"nftables": [{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": 1}}]}`, err: true},
		{name: "своя таблица без семейства", in: `{"nftables": []}`, own: []string{"vpn_panel"}, err: true},
		{name: "отрицательный контроль: пустой набор правил", in: `{"nftables": []}`, own: ownTables},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Analyze([]byte(tc.in), tc.own, lan, viaVPN)
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want err %v", err, tc.err)
			}
			if err == nil && !reflect.DeepEqual(got, Verdict{}) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestName(t *testing.T) {
	const (
		iptables = "правила старого фаервола (iptables)"
		foreign  = "чужие правила фаервола"
	)
	cases := []struct {
		c    Culprit
		want string
	}{
		{Culprit{Family: "ip", Table: "filter", Policy: "drop"}, iptables},
		{Culprit{Family: "ip6", Table: "filter"}, iptables},
		{Culprit{Family: "ip", Table: "mangle"}, iptables},
		{Culprit{Family: "inet", Table: "filter"}, foreign},
		{Culprit{Family: "ip", Table: "nat"}, foreign},
		{Culprit{Family: "ip", Table: "filter", Docker: true}, "Docker"},
		{Culprit{Family: "ip", Table: "docker-bridges"}, "Docker"},
		{Culprit{Family: "inet", Table: "docker"}, "Docker"},
		{Culprit{Family: "inet", Table: "firewalld"}, "firewalld"},
		{Culprit{Family: "ip", Table: "firewalld"}, "firewalld"},
		{Culprit{Family: "inet", Table: "custom"}, foreign},
	}
	for _, tc := range cases {
		if got := Name(tc.c); got != tc.want {
			t.Errorf("Name(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

func TestLegacyTables(t *testing.T) {
	cases := []struct {
		name string
		body *string
		want []string
	}{
		{name: "файла нет — модуль не загружен", body: nil, want: nil},
		{name: "пустой файл", body: ptr(""), want: nil},
		{name: "таблицы старого фаервола", body: ptr("nat\nfilter\n"), want: []string{"filter", "nat"}},
		{name: "повторы и пустые строки", body: ptr("filter\n\nfilter\nmangle\n"), want: []string{"filter", "mangle"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.body != nil {
				dir := filepath.Join(root, "proc", "net")
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "ip_tables_names"), []byte(*tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := LegacyTables(root); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }
