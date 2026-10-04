package metrics

import (
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
)

func TestLinkRatesAndResets(t *testing.T) {
	links := []rtnl.Link{
		{Index: 2, Name: "wan0", HasStats: true, RxBytes: 1000, TxBytes: 500},
		{Index: 3, Name: "lan0", HasStats: true, RxBytes: 100, TxBytes: 100},
		{Index: 4, Name: "lan1", HasStats: true, RxBytes: 100, TxBytes: 100},
	}
	rolesCalls := 0
	l := NewLinkSource(func() Roles { rolesCalls++; return Roles{WAN: "wan0", LANs: []string{"lan0", "lan1"}, Tunnel: "wg0"} },
		func() ([]rtnl.Link, error) { return links, nil })
	base := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return base }
	out, _ := l.read()
	if len(out) != 0 || rolesCalls != 1 {
		t.Fatalf("первый отсчёт обязан быть «неизвестно»: %v, ролей прочитано %d", out, rolesCalls)
	}
	links[0].RxBytes, links[0].TxBytes = 3000, 1500
	links[1].RxBytes, links[2].RxBytes = 300, 300
	l.now = func() time.Time { return base.Add(2 * time.Second) }
	out, _ = l.read()
	if out[RowWANRx] != 1000 || out[RowWANTx] != 500 || out[RowLANRx] != 200 || out[RowLANTx] != 0 {
		t.Fatalf("скорости: %v", out)
	}
	if _, ok := out[RowTunnelRx]; ok {
		t.Fatal("канала нет в дампе — ряд обязан быть неизвестен")
	}
	if rolesCalls != 1 {
		t.Fatal("роли перечитаны без события")
	}

	links[0].RxBytes = 10
	l.now = func() time.Time { return base.Add(3 * time.Second) }
	out, _ = l.read()
	if _, ok := out[RowWANRx]; ok {
		t.Fatal("уменьшение счётчика нарисовало бы всплеск")
	}
	if out[RowLANRx] != 0 {
		t.Fatalf("LAN пострадал от сброса WAN: %v", out)
	}

	links[0].RxBytes, links[0].Index = 5000, 9
	l.now = func() time.Time { return base.Add(4 * time.Second) }
	out, _ = l.read()
	if _, ok := out[RowWANRx]; ok {
		t.Fatal("новый номер интерфейса не распознан как сброс")
	}

	l.Invalidate()
	l.now = func() time.Time { return base.Add(5 * time.Second) }
	_, _ = l.read()
	if rolesCalls != 2 {
		t.Fatalf("после события роли не перечитаны: %d", rolesCalls)
	}
}
