package setup

import (
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

func fact(id string, a hostcaps.Answer, level string) hostcaps.Fact {
	return hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: a, Level: level, Found: "текст " + id, How: hostcaps.HowRun}
}

func counted(f hostcaps.Fact) hostcaps.Fact {
	f.How = hostcaps.HowCounter
	return f
}

func TestOfficePath(t *testing.T) {
	const cutID, offID, ownID = "surroundings.forward_cut", "surroundings.forward_off", "surroundings.own_table"
	cases := []struct {
		name     string
		st       hostcaps.Surroundings
		cut      string
		officeOK bool
		why      string
	}{
		{"срез доказан", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.Yes, hostcaps.LevelError))}}, cutID, false, ""},
		{"пересылка выключена", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			fact(cutID, hostcaps.Unknown, ""),
			fact(offID, hostcaps.Yes, hostcaps.LevelError)}}, offID, false, ""},
		{"офис закрыт защитой", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			fact(cutID, hostcaps.Unknown, ""),
			fact(ownID, hostcaps.Yes, hostcaps.LevelError)}}, ownID, false, ""},
		{"источник жив, сейчас не режет", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.Yes, hostcaps.LevelWarn))}}, "", true, ""},
		{"чужие правила не мешают", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.Yes, hostcaps.LevelInfo))}}, "", true, ""},
		{"не режет", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.No, ""))}}, "", true, ""},

		{"пересылку выключали", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.No, "")),
			fact(offID, hostcaps.Yes, hostcaps.LevelWarn)}}, "", true, ""},
		{"правила стирали", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.No, "")),
			fact(ownID, hostcaps.Yes, hostcaps.LevelWarn)}}, "", true, ""},

		{"«нет» без свидетелей", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			fact(cutID, hostcaps.No, "")}}, "", false, ""},
		{"«да» ниже ошибки без свидетелей", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			fact(cutID, hostcaps.Yes, hostcaps.LevelWarn)}}, "", false, ""},
		{"нет трафика офиса", hostcaps.Surroundings{Facts: []hostcaps.Fact{
			fact(cutID, hostcaps.Unknown, "")}}, "", false, "текст " + cutID},
		{"агент перепроверяет", hostcaps.Surroundings{Settling: true, Facts: []hostcaps.Fact{
			counted(fact(cutID, hostcaps.Yes, hostcaps.LevelError))}}, "", false, ""},
		{"факта нет", hostcaps.Surroundings{}, "", false, ""},
	}
	for _, c := range cases {
		cut, ok, why := officePath(c.st)
		got := ""
		if cut != nil {
			got = cut.ID
		}
		if got != c.cut || ok != c.officeOK || why != c.why {
			t.Errorf("%s: срез %q, проходит %v, почему %q; ждали %q, %v, %q", c.name, got, ok, why, c.cut, c.officeOK, c.why)
		}
	}
}

func TestInternetStepNeedsOffice(t *testing.T) {
	cut := fact("surroundings.forward_cut", hostcaps.Yes, hostcaps.LevelError)
	cases := []struct {
		name     string
		f        Facts
		wantDone bool
	}{
		{"интернет есть, офис проходит", Facts{Internet: "up", OfficeOK: true}, true},
		{"интернет есть, офис ещё не проверен", Facts{Internet: "up"}, true},
		{"интернет есть, офис отрезан", Facts{Internet: "up", OfficeCut: &cut}, false},
		{"интернета нет", Facts{Internet: "down"}, false},
		{"шаг пропущен при отрезанном офисе", Facts{Internet: "up", OfficeCut: &cut, Skipped: map[string]bool{"internet": true}}, true},
	}
	for _, c := range cases {
		if c.f.Skipped == nil {
			c.f.Skipped = map[string]bool{}
		}
		if got := c.f.Wizard().Set[wizard.FactInternet]; got != c.wantDone {
			t.Errorf("%s: шаг пройден %v, ждали %v", c.name, got, c.wantDone)
		}
	}
}

func TestLegacySettingsSuggest(t *testing.T) {

	f := Facts{Cards: []Card{
		{Name: "ens2", Up: true, Addresses: []string{"192.168.11.1/24"}, HasRoute: true},
		{Name: "ens3", Up: true, Addresses: []string{"10.0.2.15/24"}},
	}}
	f.Legacy = &legacyvpn.Settings{
		WAN:     legacyvpn.WAN{Card: "ens3", Method: legacyvpn.MethodPPPoE, PPPoEUser: "office", PPPoEPassword: true},
		LAN:     legacyvpn.LAN{Card: "ens2", CIDR: "192.168.11.1/24"},
		DHCP:    legacyvpn.DHCP{Subnet: "192.168.11.0/24"},
		VPN:     &legacyvpn.VPN{Protocol: legacyvpn.ProtocolOpenVPN, Endpoint: "vpn.example.net:1194"},
		Missing: []legacyvpn.Missing{{What: "диапазон выдачи адресов", Why: "файла нет"}},
	}
	if f.SuggestWAN() != "ens3" || f.ChosenLAN() != "ens2" {
		t.Fatalf("карты старого шлюза: WAN %q, LAN %q", f.SuggestWAN(), f.ChosenLAN())
	}
	if f.SuggestLANCIDR() != "192.168.11.1/24" {
		t.Fatalf("адрес офиса старого шлюза: %q", f.SuggestLANCIDR())
	}
	taken, missing := f.LegacyReport()
	if len(taken) != 4 || !strings.Contains(taken[0], "PPPoE с логином office и паролем") || !strings.Contains(taken[3], "OpenVPN") {
		t.Fatalf("отчёт: %v", taken)
	}
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "диапазон выдачи адресов: ") {
		t.Fatalf("непрочитанное: %v", missing)
	}

	f.Legacy.WAN.Card, f.Legacy.LAN.Card = "eth9", "ens3"
	if f.SuggestWAN() != "ens2" || f.ChosenLAN() != "ens3" || f.SuggestLANCIDR() == "192.168.11.1/24" {
		t.Fatalf("без карты и при пересечении: WAN %q, LAN %q, адрес %q", f.SuggestWAN(), f.ChosenLAN(), f.SuggestLANCIDR())
	}

	f.LANDraft = "ens2"
	if f.ChosenLAN() != "ens2" {
		t.Fatal("черновик проиграл подсказке")
	}
	if taken, missing := (Facts{}).LegacyReport(); taken != nil || missing != nil {
		t.Fatal("отчёт без старого шлюза")
	}
}
