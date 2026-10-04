package qosgen

import (
	"reflect"
	"strings"
	"testing"
)

func validPlan() Plan {
	return Plan{Enabled: true, WAN: "ens3", DownKbit: 100_000, UpKbit: 50_000}
}

func TestValidateOK(t *testing.T) {
	p := validPlan()
	if err := p.Validate(map[string]bool{"ens3": true}); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
}

func TestValidateDisabledSkipsChecks(t *testing.T) {
	p := Plan{Enabled: false}
	if err := p.Validate(nil); err != nil {
		t.Fatalf("disabled plan must always validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"bad iface name", func(p *Plan) { p.WAN = "ens3; rm -rf /" }},
		{"empty iface", func(p *Plan) { p.WAN = "" }},
		{"unknown iface", func(p *Plan) { p.WAN = "ens9" }},
		{"down below floor", func(p *Plan) { p.DownKbit = 999 }},
		{"up below floor", func(p *Plan) { p.UpKbit = 0 }},
		{"down above ceiling", func(p *Plan) { p.DownKbit = MaxKbit + 1 }},
	}
	for _, tc := range cases {
		p := validPlan()
		tc.mutate(&p)
		if err := p.Validate(map[string]bool{"ens3": true}); err == nil {
			t.Errorf("%s: error expected", tc.name)
		}
	}
}

func TestShapedValues(t *testing.T) {
	p := validPlan()
	if got := p.ShapedDownKbit(); got != 95_000 {
		t.Fatalf("shaped down = %d, want 95000", got)
	}
	if got := p.ShapedUpKbit(); got != 47_500 {
		t.Fatalf("shaped up = %d, want 47500", got)
	}
}

func TestCommandsDeterministic(t *testing.T) {
	p := validPlan()
	want := [][]string{
		{"qdisc", "replace", "dev", "ens3", "root", "cake", "bandwidth", "47500kbit", "ethernet"},
		{"qdisc", "replace", "dev", "ens3", "handle", "ffff:", "ingress"},
		{"filter", "replace", "dev", "ens3", "parent", "ffff:", "matchall",
			"action", "mirred", "egress", "redirect", "dev", IFBDevice},
		{"qdisc", "replace", "dev", IFBDevice, "root", "cake", "bandwidth", "95000kbit",
			"ethernet", "besteffort", "wash", "ingress"},
	}
	if got := p.Commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands mismatch:\n got %v\nwant %v", got, want)
	}
}

const tcSampleCake = `[{"kind":"cake","handle":"8001:","root":true,"refcnt":3,` +
	`"options":{"bandwidth":5937500,"diffserv":"diffserv3","flowmode":"triple-isolate",` +
	`"nat":false,"wash":false,"ingress":false,"overhead":38,"mpu":84}}]`

const tcSampleDefault = `[{"kind":"fq_codel","handle":"0:","root":true,"refcnt":2,"options":{}}]`

const tcSampleIngress = `[{"kind":"cake","handle":"8001:","root":true,"options":{"bandwidth":5937500}},` +
	`{"kind":"ingress","handle":"ffff:","parent":"ffff:fff1","options":{}}]`

func TestCakeBandwidthBytesMatchesStand(t *testing.T) {
	if got := CakeBandwidthBytes(47_500); got != 5_937_500 {
		t.Fatalf("bandwidth bytes = %d, want 5937500 (замер на живой очереди)", got)
	}
}

func TestActiveCake(t *testing.T) {
	bw, found, err := ActiveCake([]byte(tcSampleCake))
	if err != nil || !found || bw != 5_937_500 {
		t.Fatalf("ActiveCake(cake) = %d %v %v", bw, found, err)
	}
	_, found, err = ActiveCake([]byte(tcSampleDefault))
	if err != nil || found {
		t.Fatalf("ActiveCake(default qdisc) must not match, err=%v", err)
	}
	if _, _, err := ActiveCake([]byte("not json")); err == nil {
		t.Fatal("broken JSON must return error")
	}
}

func TestHasIngress(t *testing.T) {
	if !HasIngress([]byte(tcSampleIngress)) {
		t.Fatal("ingress qdisc not detected")
	}
	if HasIngress([]byte(tcSampleCake)) {
		t.Fatal("false ingress detection")
	}
}

func TestParseLinkSpeedMbit(t *testing.T) {
	cases := map[string]int{
		"1000\n": 1000,
		"-1\n":   -1,
		"":       -1,
		"junk":   -1,
		"0":      -1,
	}
	for in, want := range cases {
		if got := ParseLinkSpeedMbit(in); got != want {
			t.Errorf("ParseLinkSpeedMbit(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseLoad1(t *testing.T) {
	if got := ParseLoad1("0.17 0.13 0.06 1/163 1652\n"); got != "0.17" {
		t.Fatalf("load1 = %q", got)
	}
	if got := ParseLoad1(""); got != "" {
		t.Fatalf("empty loadavg: %q", got)
	}
}

func TestTunnelQueueCommands(t *testing.T) {
	p := Plan{Enabled: true, WAN: "ens3", Tunnel: "wg-vpn0", DownKbit: 100_000, UpKbit: 50_000}
	if err := p.Validate(map[string]bool{"ens3": true}); err != nil {
		t.Fatalf("канала ещё нет в списке карт — это не повод отказывать: %v", err)
	}
	cmds := p.Commands()
	want := [][]string{
		{"qdisc", "replace", "dev", "wg-vpn0", "root", "cake", "bandwidth", "45000kbit", "overhead", "60"},
		{"qdisc", "replace", "dev", "wg-vpn0", "handle", "ffff:", "ingress"},
		{"filter", "replace", "dev", "wg-vpn0", "parent", "ffff:", "matchall",
			"action", "mirred", "egress", "redirect", "dev", "ifb-vpn1"},
		{"qdisc", "replace", "dev", "ifb-vpn1", "root", "cake", "bandwidth", "90000kbit",
			"overhead", "60", "besteffort", "wash", "ingress"},
	}
	got := cmds[len(cmds)-len(want):]
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Fatalf("команда %d:\n получено: %v\n ожидалось: %v", i, got[i], want[i])
		}
	}

	if p.TunnelDownKbit() >= p.ShapedDownKbit() || p.TunnelUpKbit() >= p.ShapedUpKbit() {
		t.Fatalf("очередь канала (%d/%d) не уже очереди провайдера (%d/%d)",
			p.TunnelDownKbit(), p.TunnelUpKbit(), p.ShapedDownKbit(), p.ShapedUpKbit())
	}

	if IFBDevice == IFBTunnelDevice {
		t.Fatal("вход провайдера и вход канала не могут делить одно устройство")
	}
}

func TestNoTunnelNoTunnelQueue(t *testing.T) {
	p := Plan{Enabled: true, WAN: "ens3", DownKbit: 100_000, UpKbit: 50_000}
	if len(p.TunnelCommands()) != 0 {
		t.Fatal("без защищённого канала его очереди быть не должно")
	}
	for _, c := range p.Commands() {
		if strings.Contains(strings.Join(c, " "), IFBTunnelDevice) {
			t.Fatalf("в белом режиме нет устройства входа канала: %v", c)
		}
	}
}

func TestTunnelNameValidated(t *testing.T) {
	p := Plan{Enabled: true, WAN: "ens3", Tunnel: "wg vpn0; rm -rf /", DownKbit: 100_000, UpKbit: 50_000}
	if err := p.Validate(map[string]bool{"ens3": true}); err == nil {
		t.Fatal("имя канала обязано проверяться белым списком — оно идёт в argv")
	}
}

func TestParseDroppedSumsAllQueues(t *testing.T) {
	out := []byte(`qdisc cake 8003: root refcnt 2 bandwidth 45Mbit
 Sent 21935 bytes 250 pkt (dropped 7, overlimits 15 requeues 0)
 backlog 0b 0p requeues 0
qdisc ingress ffff: parent ffff:fff1 ----------------
 Sent 100 bytes 2 pkt (dropped 5, overlimits 0 requeues 0)`)
	if got := ParseDropped(out); got != 12 {
		t.Fatalf("отброшено = %d, ожидалось 12", got)
	}
}

func TestParseDroppedOnGarbageIsZero(t *testing.T) {
	for _, in := range []string{"", "нет таких слов", "dropped abc"} {
		if got := ParseDropped([]byte(in)); got != 0 {
			t.Errorf("на входе %q счётчик %d, ожидался 0", in, got)
		}
	}
}
