package diagfacts

import "testing"

const neighSample = `[{"dst":"192.168.11.100","dev":"ens4","lladdr":"52:54:00:12:34:10","state":["REACHABLE"]},` +
	`{"dst":"192.168.11.254","dev":"ens4","lladdr":"52:54:00:70:1d:a4","state":["STALE"]},` +
	`{"dst":"192.168.11.77","dev":"ens4","state":["FAILED"]},` +
	`{"dst":"fe80::1","dev":"ens4","lladdr":"52:54:00:12:34:10","state":["REACHABLE"]}]`

const setSample = `{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},` +
	`{"set":{"family":"inet","name":"diag_foreign_dns","table":"vpn_panel","type":"ipv4_addr","handle":3,"flags":["dynamic","timeout"],"timeout":604800,"size":4096,` +
	`"elem":[{"elem":{"val":"192.168.11.100","expires":604799,"counter":{"packets":2,"bytes":114}}}]}}]}`

const linkSample = `[{"ifindex":3,"ifname":"ens4","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,` +
	`"stats64":{"rx":{"bytes":100,"packets":969,"errors":0,"dropped":3,"crc_errors":2,"multicast":0},` +
	`"tx":{"bytes":100,"packets":245,"errors":0,"dropped":0,"carrier_errors":0,"collisions":1}}}]`

const arpingSample = "ARPING 192.168.11.100 from 192.168.11.1 ens4\n" +
	"Unicast reply from 192.168.11.100 [52:54:00:12:34:10]  0.810ms\n" +
	"Unicast reply from 192.168.11.100 [52:54:00:12:34:10]  1.066ms\n" +
	"Unicast reply from 192.168.11.100 [52:54:00:12:34:10]  0.900ms\n" +
	"Sent 5 probes (1 broadcast(s))\nReceived 3 response(s)\n"

func TestParseNeighboursSkipsFailedAndIPv6(t *testing.T) {
	n, err := ParseNeighbours([]byte(neighSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 2 || n[0].IP != "192.168.11.100" || n[0].MAC != "52:54:00:12:34:10" || n[1].State != "STALE" {
		t.Fatalf("neighbours: %+v", n)
	}
}

func TestParseSet(t *testing.T) {
	e, err := ParseSet([]byte(setSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 1 || e[0].IP != "192.168.11.100" || e[0].Packets != 2 || e[0].Expires != 604799 {
		t.Fatalf("set: %+v", e)
	}
	if e, _ := ParseSet([]byte(`{"nftables":[{"metainfo":{}}]}`)); len(e) != 0 {
		t.Fatal("пустой набор — пустой список")
	}
}

func TestParseLink(t *testing.T) {
	ls, err := ParseLink([]byte(linkSample), "100\n", "half\n")
	if err != nil {
		t.Fatal(err)
	}
	if ls.Name != "ens4" || ls.SpeedMbit != 100 || ls.Duplex != "half" || ls.RxCRC != 2 || ls.Collisions != 1 || ls.RxDropped != 3 {
		t.Fatalf("link: %+v", ls)
	}
	ls, _ = ParseLink([]byte(linkSample), "-1", "unknown")
	if ls.SpeedMbit != -1 || ls.Duplex != "unknown" {
		t.Fatalf("виртуальная карта: %+v", ls)
	}
}

func TestParseArping(t *testing.T) {
	r := ParseArping("192.168.11.100", []byte(arpingSample))
	if r.Sent != 5 || r.Received != 3 || r.MAC != "52:54:00:12:34:10" {
		t.Fatalf("arping: %+v", r)
	}
	if r.LossPercent() != 40 || r.MinMs != 0.81 || r.MaxMs != 1.07 || r.AvgMs != 0.93 {
		t.Fatalf("статистика: %+v loss=%d", r, r.LossPercent())
	}
	if r.JitterMs <= 0 || r.JitterMs > 0.2 {
		t.Fatalf("джиттер: %v", r.JitterMs)
	}
	empty := ParseArping("10.0.0.9", []byte("Sent 5 probes (1 broadcast(s))\nReceived 0 response(s)\n"))
	if empty.LossPercent() != 100 || empty.Received != 0 {
		t.Fatalf("без ответов: %+v", empty)
	}
}

func TestWithDevFillsMissingOnly(t *testing.T) {
	ns := WithDev([]Neighbour{{IP: "10.0.0.2", MAC: "aa"}, {IP: "10.0.0.3", MAC: "bb", Dev: "ens9"}}, "ens4")
	if ns[0].Dev != "ens4" || ns[1].Dev != "ens9" {
		t.Fatalf("карты: %+v", ns)
	}
}
