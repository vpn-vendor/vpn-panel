package dnsinfra

import "testing"

func TestParse(t *testing.T) {
	out := []byte("149.112.112.112 . ttl 180 ping 4 var 49 rtt 200 rto 200 tA 0 tAAAA 0 tother 0 ednsknown 1 edns 0 delay 0 lame dnssec 0 rec 0 A 0 other 0\n" +
		"9.9.9.9 . ttl 180 ping 2 var 75 rtt 302 rto 302 tA 0 tAAAA 0 tother 0\n" +
		"192.0.2.53 example. ttl 10 ping 1 var 1 rtt 1 rto 1\n" +
		"мусор без адреса\n")
	all := Parse(out, nil)
	if len(all) != 3 || all[0].IP != "149.112.112.112" || all[0].PingMs != 4 || all[0].VarMs != 49 || all[0].TTL != 180 || all[1].PingMs != 2 {
		t.Fatalf("%+v", all)
	}
	only := Parse(out, []string{"9.9.9.9", "149.112.112.112"})
	if len(only) != 2 {
		t.Fatalf("фильтр по вышестоящим: %+v", only)
	}
}
