package metrics

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
)

func TestVoiceTinByCount(t *testing.T) {
	if i, ok := voiceTin(3); !ok || i != 2 {
		t.Fatal("diffserv3: голос — третий уровень")
	}
	if i, ok := voiceTin(4); !ok || i != 3 {
		t.Fatal("diffserv4: голос — четвёртый уровень")
	}
	if _, ok := voiceTin(1); ok {
		t.Fatal("besteffort без голосового уровня")
	}
}

func TestQoSDelayAndDropRate(t *testing.T) {
	links := []rtnl.Link{{Index: 2, Name: "ens3"}, {Index: 7, Name: "ovpn-vpn0"}, {Index: 9, Name: "ifb-vpn0"}}
	qd := []rtnl.Qdisc{
		{IfIndex: 2, Kind: "cake", Tins: []rtnl.Tin{{}, {}, {AvgDelayUs: 1500, DroppedPackets: 10}}},
		{IfIndex: 9, Kind: "cake", Tins: []rtnl.Tin{{AvgDelayUs: 99}}},
		{IfIndex: 3, Kind: "fq_codel"},
	}
	src := NewQoSSource(func() Roles { return Roles{WAN: "ens3", Tunnel: "ovpn-vpn0"} },
		func() ([]rtnl.Qdisc, error) { return qd, nil }, func() ([]rtnl.Link, error) { return links, nil })
	base := time.Unix(1_700_000_000, 0)
	src.now = func() time.Time { return base }
	out, _ := src.read()
	if out[RowWANVoiceDelay] != 1.5 {
		t.Fatalf("задержка: %v", out)
	}
	if _, ok := out[RowWANVoiceDrops]; ok {
		t.Fatal("первый отсчёт сбросов обязан быть неизвестен")
	}
	if _, ok := out[RowTunnelVoiceDelay]; ok {
		t.Fatal("на карте канала нет очереди — ряд неизвестен")
	}
	qd[0].Tins[2].DroppedPackets = 16
	src.now = func() time.Time { return base.Add(2 * time.Second) }
	out, _ = src.read()
	if out[RowWANVoiceDrops] != 3 {
		t.Fatalf("сбросов в секунду: %v", out)
	}

	qd[0].Tins[2].DroppedPackets = 1
	src.now = func() time.Time { return base.Add(3 * time.Second) }
	out, _ = src.read()
	if _, ok := out[RowWANVoiceDrops]; ok {
		t.Fatal("уменьшение счётчика сбросов нарисовало бы всплеск")
	}
}

func TestVoiceNormComesFromTheQueueItself(t *testing.T) {
	links := []rtnl.Link{{Index: 2, Name: "ens3"}}
	qd := []rtnl.Qdisc{{IfIndex: 2, Kind: "cake", Tins: []rtnl.Tin{{}, {}, {AvgDelayUs: 900, TargetUs: 18200, IntervalUs: 113200}}}}
	src := NewQoSSource(func() Roles { return Roles{WAN: "ens3"} },
		func() ([]rtnl.Qdisc, error) { return qd, nil }, func() ([]rtnl.Link, error) { return links, nil })
	if _, ok := VoiceNormFor(RowWANVoiceDelay); ok {
		t.Fatal("до первого чтения нормы быть не может")
	}
	if _, err := src.read(); err != nil {
		t.Fatal(err)
	}
	n, ok := VoiceNormFor(RowWANVoiceDelay)
	if !ok || n.TargetMs != 18.2 || n.IntervalMs != 113.2 {
		t.Fatalf("норма очереди: %+v %v", n, ok)
	}
	if _, ok := VoiceNormFor(RowTunnelVoiceDelay); ok {
		t.Fatal("у канала без очереди нормы нет")
	}
	qd[0].Kind = "fq_codel"
	qd[0].Tins = nil
	if _, err := src.read(); err != nil {
		t.Fatal(err)
	}
	if _, ok := VoiceNormFor(RowWANVoiceDelay); ok {
		t.Fatal("очередь снята — норма обязана исчезнуть")
	}
}
