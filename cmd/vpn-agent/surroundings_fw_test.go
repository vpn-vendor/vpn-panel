package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftforeign"
)

func TestWitnessVerdict(t *testing.T) {
	var w witnessState
	steps := []struct {
		name                string
		handle, early, late int64
		ok                  bool
		want                witnessVerdict
	}{
		{"первое чтение — база", 5, 100, 100, true, witnessNone},
		{"трафика нет — база держится", 5, 100, 100, true, witnessNone},
		{"прошли оба свидетеля", 5, 110, 110, true, witnessPass},
		{"трафика нет — вердикт остаётся", 5, 110, 110, true, witnessPass},

		{"часть не дошла", 5, 140, 111, true, witnessPass},
		{"до выхода не дошло ни одного", 5, 150, 111, true, witnessCut},
		{"тишина — срез держится", 5, 150, 111, true, witnessCut},
		{"пакет, пойманный между свидетелями, дошёл", 5, 150, 112, true, witnessPass},
		{"таблицу пересоздали — база заново", 6, 0, 0, true, witnessNone},
		{"счётчик ушёл назад — база заново", 6, 0, 0, true, witnessNone},
		{"свидетелей нет", 0, 0, 0, false, witnessNone},
	}
	for _, s := range steps {
		if got := w.observe(s.handle, s.early, s.late, s.ok); got != s.want {
			t.Fatalf("%s: %v, ждали %v", s.name, got, s.want)
		}
	}
}

func TestParseWitness(t *testing.T) {
	out := []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"table":{"family":"inet","name":"vpn_panel","handle":12}},` +
		`{"counter":{"family":"inet","name":"seen_early","table":"vpn_panel","handle":3,"packets":10,"bytes":600}},` +
		`{"counter":{"family":"inet","name":"seen_late","table":"vpn_panel","handle":4,"packets":7,"bytes":420}},` +
		`{"rule":{"family":"inet","table":"vpn_panel","chain":"witness_early","handle":9,"expr":[{"counter":"seen_early"}]}}]}`)
	h, e, l, ok := parseWitness(out)
	if !ok || h != 12 || e != 10 || l != 7 {
		t.Fatalf("parseWitness = %d %d %d %v", h, e, l, ok)
	}

	if _, _, _, ok := parseWitness([]byte(`{"nftables":[{"table":{"family":"inet","name":"vpn_panel","handle":12}}]}`)); ok {
		t.Fatal("свидетели найдены там, где их нет")
	}
}

func TestForwardCutFact(t *testing.T) {
	oldFilter := nftforeign.Culprit{Family: "ip", Table: "filter", Policy: "drop", Drops: true, Opaque: true}
	docker := nftforeign.Culprit{Family: "ip", Table: "filter", Policy: "drop", Docker: true}
	outside := nftforeign.Culprit{Family: "inet", Table: "my", Policy: "drop", OutsideWitness: true}
	persistent := ruleSource{"netfilter-persistent", "сохранённые правила iptables", "Сохранённые правила iptables", "Система восстанавливает."}
	roles := forwardInputs{held: true, working: true, analyzed: true, witnessCaps: hostcaps.Yes}
	with := func(base forwardInputs, mod func(*forwardInputs)) forwardInputs { mod(&base); return base }
	for _, tc := range []struct {
		name    string
		in      forwardInputs
		answer  hostcaps.Answer
		level   string
		value   string
		counter bool
		legacy  bool
	}{
		{"свидетель видит срез старого скрипта",
			with(roles, func(i *forwardInputs) {
				i.witness, i.verdict, i.legacyGateway = true, witnessCut, true
				i.culprits, i.sources = []nftforeign.Culprit{oldFilter}, []ruleSource{persistent}
			}),
			hostcaps.Yes, hostcaps.LevelError, "старый скрипт vpn.sh", true, true},
		{"свидетель видит срез без разбора",
			with(roles, func(i *forwardInputs) { i.witness, i.verdict, i.analyzed = true, witnessCut, false }),
			hostcaps.Yes, hostcaps.LevelError, "чужие правила фаервола", true, false},
		{"Docker режет",
			with(roles, func(i *forwardInputs) {
				i.witness, i.verdict, i.legacyGateway, i.culprits = true, witnessCut, true, []nftforeign.Culprit{docker}
			}),
			hostcaps.Yes, hostcaps.LevelError, "Docker", true, false},
		{"проходит, источник с сохранённым запретом",
			with(roles, func(i *forwardInputs) { i.witness, i.verdict, i.sources = true, witnessPass, []ruleSource{persistent} }),
			hostcaps.Yes, hostcaps.LevelWarn, "сохранённые правила iptables", true, false},
		{"проходит, чужое без источника",
			with(roles, func(i *forwardInputs) {
				i.witness, i.verdict, i.culprits = true, witnessPass, []nftforeign.Culprit{oldFilter}
			}),
			hostcaps.Yes, hostcaps.LevelInfo, "правила старого фаервола (iptables)", true, false},
		{"проходит, чужого нет",
			with(roles, func(i *forwardInputs) { i.witness, i.verdict = true, witnessPass }),
			hostcaps.No, "", "", true, false},

		{"проходит, но виновник вне окна",
			with(roles, func(i *forwardInputs) {
				i.witness, i.verdict, i.culprits = true, witnessPass, []nftforeign.Culprit{outside}
			}),
			hostcaps.Unknown, "", "чужие правила фаервола", false, false},

		{"трафика не было",
			with(roles, func(i *forwardInputs) { i.witness = true }),
			hostcaps.Unknown, "", "", false, false},
		{"аварийный набор сторожа",
			with(roles, func(i *forwardInputs) { i.emergency = true }),
			hostcaps.Unknown, "", "", false, false},
		{"закрытый офис",
			with(roles, func(i *forwardInputs) { i.working = false }),
			hostcaps.Unknown, "", "", false, false},
		{"система без свидетелей",
			with(roles, func(i *forwardInputs) { i.witnessCaps = hostcaps.No }),
			hostcaps.Unknown, "", "", false, false},
		{"роли есть, свидетелей нет, чужое с запретом — не «да»",
			with(roles, func(i *forwardInputs) { i.culprits = []nftforeign.Culprit{oldFilter} }),
			hostcaps.Unknown, "", "правила старого фаервола (iptables)", false, false},
		{"до ролей: старый запрет предупреждает",
			forwardInputs{analyzed: true, legacyGateway: true, culprits: []nftforeign.Culprit{oldFilter},
				sources: []ruleSource{persistent}},
			hostcaps.Yes, hostcaps.LevelWarn, "старый скрипт vpn.sh", false, true},
		{"до ролей: только таблицы iptables-legacy",
			forwardInputs{analyzed: true, legacyTables: []string{"filter"}},
			hostcaps.Unknown, "", "правила старого фаервола (iptables)", false, false},
		{"до ролей: чисто", forwardInputs{analyzed: true}, hostcaps.No, "", "", false, false},
		{"разбор не удался", forwardInputs{}, hostcaps.Unknown, "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := forwardCutFact(tc.in)
			if f.Answer != tc.answer || f.Level != tc.level || f.Value != tc.value {
				t.Fatalf("ответ %s/%s/%q, ждали %s/%s/%q", f.Answer, f.Level, f.Value, tc.answer, tc.level, tc.value)
			}
			if (f.How == hostcaps.HowCounter) != tc.counter {
				t.Fatalf("способ %q: доказательство счётчиками %v", f.How, tc.counter)
			}
			if (f.Cause == hostcaps.CauseLegacy) != tc.legacy {
				t.Fatalf("причина %q", f.Cause)
			}
			if f.Answer == hostcaps.Yes && f.Found == "" {
				t.Fatal("ответ «да» без объяснения")
			}
			if f.Answer == hostcaps.Unknown && (tc.in.analyzed || tc.in.held) && f.Found == "" {
				t.Fatal("«неизвестно» без объяснения")
			}
			for _, bad := range []string{"Программа старый", "(чужие правила фаервола)", "Программа сохранённые", "Программа правила"} {
				if strings.Contains(f.Found, bad) {
					t.Fatalf("текст склеен из имени: %q", f.Found)
				}
			}
		})
	}
}

func TestIptablesSaveDrops(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"политика старого скрипта", "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", true},
		{"правило REJECT", "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i ens3 -o ens2 -j REJECT --reject-with icmp-port-unreachable\nCOMMIT\n", true},
		{"всё разрешено", "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i ens3 -o tun0 -j ACCEPT\nCOMMIT\n", false},
		{"запрет только испорченных", "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -m conntrack --ctstate INVALID -j DROP\nCOMMIT\n", false},
		{"запрет одного порта", "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -p tcp --dport 25 -j REJECT\nCOMMIT\n", false},
		{"запрет в чужой таблице", "*mangle\n:FORWARD DROP [0:0]\nCOMMIT\n*filter\n:FORWARD ACCEPT [0:0]\nCOMMIT\n", false},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
		if err := os.WriteFile(p, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := iptablesSaveDrops(p); got != tc.want {
			t.Fatalf("%s: %v", tc.name, got)
		}
	}
	if iptablesSaveDrops(filepath.Join(dir, "нет")) {
		t.Fatal("нет файла — нет запрета")
	}
}

func TestProbeOwnTable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nft := writer{pid: 7, comm: "nft", unit: "nftables.service"}
	for _, tc := range []struct {
		name          string
		v             guardView
		offAns, ownAn hostcaps.Answer
		offLv, ownLv  string
	}{
		{"ничего не было", guardView{working: true, forward: true}, hostcaps.No, hostcaps.No, "", ""},
		{"стёрли и вернули", guardView{working: true, forward: true, erasedAt: now, eraser: nft},
			hostcaps.No, hostcaps.Yes, "", hostcaps.LevelWarn},
		{"перетягивают", guardView{working: true, forward: true, erasedAt: now, eraser: nft, emergency: true},
			hostcaps.No, hostcaps.Yes, "", hostcaps.LevelError},
		{"не вернулось", guardView{working: true, forward: true, erasedAt: now, failed: true, emergency: true},
			hostcaps.No, hostcaps.Yes, "", hostcaps.LevelError},
		{"пересылка выключена", guardView{working: true, forward: true, fwdOffNow: true, fwdOffAt: now},
			hostcaps.Yes, hostcaps.No, hostcaps.LevelError, ""},
		{"пересылку вернули", guardView{working: true, forward: true, fwdOffAt: now.Add(-time.Minute)},
			hostcaps.Yes, hostcaps.No, hostcaps.LevelWarn, ""},
		{"давно вернули", guardView{working: true, forward: true, fwdOffAt: now.Add(-guardCalm)},
			hostcaps.No, hostcaps.No, "", ""},
		{"до ролей пересылка не наша", guardView{fwdOffNow: true}, hostcaps.No, hostcaps.No, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := probeOwnTable(tc.v, now)
			off, own := obs[0].Fact, obs[1].Fact
			if off.Answer != tc.offAns || off.Level != tc.offLv || own.Answer != tc.ownAn || own.Level != tc.ownLv {
				t.Fatalf("пересылка %s/%s, таблица %s/%s", off.Answer, off.Level, own.Answer, own.Level)
			}
			if own.Answer == hostcaps.Yes && tc.v.eraser.pid != 0 && !strings.Contains(own.Found, "nftables") {
				t.Fatalf("виновник не назван: %q", own.Found)
			}
		})
	}
}

func TestWriterName(t *testing.T) {
	for _, tc := range []struct {
		w    writer
		want string
	}{
		{writer{unit: "nftables.service", comm: "nft"}, "служба nftables"},
		{writer{unit: "netfilter-persistent.service", comm: "iptables-nft-re"}, "восстановление сохранённых правил iptables"},
		{writer{comm: "dockerd"}, "Docker"},
		{writer{unit: "session-3.scope", comm: "nft"}, "команда в консоли"},
		{writer{comm: "iptables-nft-re"}, "команда iptables"},
		{writer{comm: "nft"}, "команда nft"},
		{writer{}, ""},
	} {
		if got := writerName(tc.w); got != tc.want {
			t.Fatalf("%+v: %q, ждали %q", tc.w, got, tc.want)
		}
	}
}

func TestDHCPLANFact(t *testing.T) {
	got := dhcpLANFact([]dhcpSeen{{"aa:bb:cc:00:00:01", "192.168.1.1"}, {"aa:bb:cc:00:00:02", "192.168.1.254"},
		{"aa:bb:cc:00:00:01", "192.168.1.1"}}, true, true)
	if got.Answer != hostcaps.Yes || got.Level != hostcaps.LevelWarn || got.Value != "192.168.1.1, 192.168.1.254" || got.Reset {
		t.Fatalf("увиденное: %+v", got)
	}
	if f := dhcpLANFact(nil, true, true); f.Answer != hostcaps.Unknown || f.Found == "" || !f.Reset {
		t.Fatalf("окно открыто кнопкой: %+v", f)
	}

	if f := dhcpLANFact(nil, true, false); f.Answer != hostcaps.Unknown || f.Reset {
		t.Fatalf("окно после перезагрузки: %+v", f)
	}
	if f := dhcpLANFact(nil, false, true); f.Answer != hostcaps.No || f.Reset {
		t.Fatalf("окно прошло: %+v", f)
	}
	plan := &heldPlan{lans: []string{"ens4"}}
	for _, tc := range []struct {
		name  string
		v     guardView
		built bool
		caps  hostcaps.Answer
	}{
		{"до ролей", guardView{}, false, hostcaps.Yes},
		{"аварийный набор", guardView{held: true, working: true, emergency: true, plan: plan}, true, hostcaps.Yes},
		{"закрытый офис", guardView{held: true, plan: plan}, true, hostcaps.Yes},
		{"система не умеет", guardView{held: true, working: true, plan: plan}, false, hostcaps.No},
		{"паспорт не ответил", guardView{held: true, working: true, plan: plan}, false, hostcaps.Unknown},
		{"таблица ещё не построена", guardView{held: true, working: true, plan: plan}, false, hostcaps.Yes},
	} {
		obs := probeDHCPLAN(tc.v, tc.built, false, tc.caps)

		if f := obs[0].Fact; f.Answer != hostcaps.Unknown || f.Found == "" || obs[0].moving || obs[0].hold {
			t.Fatalf("%s: %+v", tc.name, obs[0])
		}
	}
	if a, b := probeDHCPLAN(guardView{}, false, false, hostcaps.Yes)[0].Found,
		probeDHCPLAN(guardView{held: true, plan: plan}, true, false, hostcaps.Yes)[0].Found; a == b {
		t.Fatal("«ролей нет» и «офис закрыт» объясняются одинаково")
	}
}

func TestParseSeen(t *testing.T) {
	out := []byte(`{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"dhcp_seen","table":"vpn_panel_dhcp",` +
		`"type":["ether_addr","ipv4_addr"],"handle":2,"size":254,"flags":["timeout","dynamic"],"timeout":345600,` +
		`"elem":[{"elem":{"val":{"concat":["52:54:00:12:34:56","192.168.1.1"]},"timeout":345600,"expires":345000}},` +
		`{"concat":["52:54:00:12:34:57","192.168.1.2"]},{"elem":{"val":{"concat":["мусор"]}}}]}}]}`)
	got := parseSeen(out)
	if len(got) != 2 || got[0].addr != "192.168.1.1" || got[1].mac != "52:54:00:12:34:57" {
		t.Fatalf("parseSeen = %+v", got)
	}
	win := []byte(`{"nftables":[{"set":{"name":"dhcp_window","elem":[{"elem":{"val":67,"timeout":86400,"expires":86000}}]}}]}`)
	if len(setElems(win)) != 1 || len(setElems([]byte(`{"nftables":[{"set":{"name":"dhcp_window"}}]}`))) != 0 {
		t.Fatal("окно наблюдения прочитано неверно")
	}
}

func TestLeaseServer(t *testing.T) {
	dir := t.TempDir()
	nd := filepath.Join(dir, "networkd")
	nm := filepath.Join(dir, "nm")
	if err := os.WriteFile(nd, []byte("# This is private data.\nADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nm, []byte("[device]\nmanaged=true\n\n[dhcp4]\ndhcp4.dhcp_lease_time=864000\ndhcp4.dhcp_server_identifier=192.168.178.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := leaseServer(nd, "SERVER_ADDRESS"); got != "192.168.1.1" {
		t.Fatalf("networkd: %q", got)
	}
	if got := leaseServer(nm, "dhcp4.dhcp_server_identifier"); got != "192.168.178.1" {
		t.Fatalf("NetworkManager: %q", got)
	}
	if got := leaseServer(nm, "SERVER_ADDRESS"); got != "" {
		t.Fatalf("чужой ключ: %q", got)
	}
}
