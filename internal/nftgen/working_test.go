package nftgen

import "testing"

const (
	listedWorking = `table inet vpn_panel { # handle 7
	set diag_foreign_dns { # handle 1
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1d
		counter
		elements = { 192.168.77.100 expires 23h59m counter packets 2 bytes 120 }
	}
	chain postrouting { # handle 6
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "ens3" } masquerade # handle 12
	}
	chain forward { # handle 8
		type filter hook forward priority filter; policy drop;
		iifname { "ens4" } oifname { "ens3" } accept # handle 20
	}
}
`

	listedDockerAndLockdown = `table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.17.0.0/16 oifname != "docker0" masquerade
	}
}
table inet vpn_panel {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`

	staticLockdown = `table inet vpn_panel
delete table inet vpn_panel
table inet vpn_panel {
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`

	listedMasqueradeWords = `table inet vpn_panel {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		counter comment "здесь нет masquerade { и # нет"
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		oifname "ens3" masquerade
	}
}
`
	jsonWorking = `{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "vpn_panel", "handle": 7}},
{"chain": {"family": "inet", "table": "vpn_panel", "name": "postrouting", "handle": 6, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"rule": {"family": "inet", "table": "vpn_panel", "chain": "postrouting", "handle": 12, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["ens3"]}}}, {"masquerade": null}]}}]}`
	jsonLockdown = `{"nftables": [{"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "vpn_panel", "handle": 9}},
{"chain": {"family": "inet", "table": "vpn_panel", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 1, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 4, "expr": [{"masquerade": null}]}}]}`
)

func TestIsWorking(t *testing.T) {
	white := FirewallPlan{WANs: []string{"ens3"}, LANs: []FirewallLAN{{Name: "ens4", CIDR: "192.168.77.1/24"}}}
	black := blackPlan()
	for _, c := range []struct {
		name    string
		ruleset string
		want    bool
	}{
		{"наш файл, прямой режим", string(white.Generate(Caps{})), true},
		{"наш файл, защищённый режим со свидетелями", string(black.Generate(Caps{Witness: true})), true},
		{"вывод nft list -a", listedWorking, true},
		{"JSON рабочего набора", jsonWorking, true},
		{"аварийный набор по последней конфигурации", string(white.Lockdown()), false},
		{"статичный аварийный набор", staticLockdown, false},
		{"маскарад только в чужой таблице", listedDockerAndLockdown, false},
		{"маскарад в комментарии и в фильтре", listedMasqueradeWords, false},
		{"JSON аварийного набора с чужим маскарадом", jsonLockdown, false},
		{"таблица наблюдения", ProbeDHCPWatch().Create(DHCPFresh, DHCPWindow), false},
		{"пусто", "", false},
		{"битый JSON", `{"nftables": [`, false},
	} {
		if got := IsWorking([]byte(c.ruleset)); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}
