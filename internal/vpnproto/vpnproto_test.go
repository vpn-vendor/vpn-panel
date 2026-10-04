package vpnproto_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/ovpngen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
	"github.com/vpn-vendor/vpn-panel-core/internal/wggen"
)

var shapes = map[vpndriver.Protocol]string{
	wggen.ID:   "[Interface]\nPrivateKey = x\n\n[Peer]\nEndpoint = a:1\n",
	ovpngen.ID: "client\nremote vpn.example.net 1194\n<ca>\n-----BEGIN CERTIFICATE-----\n</ca>\n",
}

func TestEveryModuleHasShapeAndOnlyItsOwnDetectorMatches(t *testing.T) {
	for _, d := range vpnproto.All() {
		text, ok := shapes[d.ID]
		if !ok {
			t.Fatalf("у протокола %s нет образца файла для матрицы распознавания", d.ID)
		}
		got, err := vpnproto.Detect(text)
		if err != nil || got.ID != d.ID {
			t.Errorf("образец %s: узнан как %q (%v)", d.ID, got.ID, err)
		}
	}
}

func TestGarbageAndAmbiguityAreRefused(t *testing.T) {
	for _, bad := range []string{"", "# только комментарий\n", "hello\n"} {
		if _, err := vpnproto.Detect(bad); err == nil {
			t.Errorf("мусор принят за файл подключения: %q", bad)
		}
	}
	_, err := vpnproto.Detect(shapes[wggen.ID] + shapes[ovpngen.ID])
	if err == nil || !strings.Contains(err.Error(), "похож сразу на") {
		t.Fatalf("файл двух протоколов обязан быть отвергнут как неоднозначный: %v", err)
	}
}

func TestParseHasNoDefaultAndStoredUpgradesOldRecords(t *testing.T) {
	if vpnproto.Known(vpnproto.Parse("")) || vpnproto.Known(vpnproto.Parse("ipsec")) {
		t.Fatal("пустое или незнакомое принято за протокол")
	}
	if vpnproto.Parse(" OpenVPN ") != ovpngen.ID || vpnproto.Stored("") != wggen.ID || vpnproto.Stored("openvpn") != ovpngen.ID {
		t.Fatal("разбор имени протокола")
	}
	if vpnproto.Iface("ipsec") != "" {
		t.Fatal("незнакомый протокол не получает чужой интерфейс")
	}
}

func TestDescriptorsAreComplete(t *testing.T) {
	ids, ifaces := map[vpndriver.Protocol]bool{}, map[string]bool{}
	for _, d := range vpnproto.All() {
		if d.ID == "" || d.Label == "" || d.Iface == "" || d.Hint == "" || len(d.FileExts) == 0 ||
			len(d.Transports) == 0 || len(d.Packages) == 0 || d.Marks == nil || d.Passport == nil || d.CheckMeta == nil {
			t.Errorf("описание %q неполное", d.ID)
			continue
		}
		if ids[d.ID] || ifaces[d.Iface] {
			t.Errorf("повтор идентификатора или интерфейса: %s %s", d.ID, d.Iface)
		}
		ids[d.ID], ifaces[d.Iface] = true, true
		p := d.Passport("")
		if p.Protocol != d.ID || p.Transport != d.Transports[0] {
			t.Errorf("%s: паспорт %s/%s", d.ID, p.Protocol, p.Transport)
		}
		for _, tr := range d.Transports {
			if d.Passport(tr).Transport != tr {
				t.Errorf("%s: транспорт %s потерян в паспорте", d.ID, tr)
			}
		}
	}
	if got, want := vpnproto.Iface(wggen.ID)+" "+vpnproto.Iface(ovpngen.ID), "wg-vpn0 ovpn-vpn0"; got != want {
		t.Fatalf("имена интерфейсов вечные: %q", got)
	}
}

func TestAgentOwnsRoutesForEveryProtocol(t *testing.T) {
	for _, d := range vpnproto.All() {
		if d.Passport("").ManagesRoutes {
			t.Fatalf("%s: правила маршрутов ставит протокол — перезапуск канала снимет их вместе с ним", d.ID)
		}
	}
}

func TestStaleAfterComesFromTheProtocolBudget(t *testing.T) {
	wg, _ := vpnproto.Passport(wggen.ID, "")
	ov, _ := vpnproto.Passport(ovpngen.ID, vpndriver.TransportUDP)
	if wg.StaleAfter() != 210*time.Second || ov.StaleAfter() != 130*time.Second {
		t.Fatalf("пороги: %s %s", wg.StaleAfter(), ov.StaleAfter())
	}
}

func TestPauseCapabilityIsDeclaredNotGuessed(t *testing.T) {
	wg, _ := vpnproto.Passport(wggen.ID, "")
	ov, _ := vpnproto.Passport(ovpngen.ID, vpndriver.TransportUDP)
	if !ov.CanPause || wg.CanPause {
		t.Fatal("пауза попыток: у протокола-демона есть, у протокола без процесса — нет")
	}
}

func TestTunnelMTUFromModuleOverheads(t *testing.T) {
	if vpndriver.TunnelMTU(1500, ovpngen.OverheadIPv4) != 1448 || vpndriver.TunnelMTU(1500, wggen.OverheadIPv4) != 1440 {
		t.Fatal("размер пакета канала из оверхеда модуля")
	}
}
