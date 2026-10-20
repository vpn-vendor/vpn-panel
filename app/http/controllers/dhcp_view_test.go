package controllers

import "testing"

func TestDhcpRowsMergeLeasesAndReservations(t *testing.T) {
	rows := dhcpRows(
		[]leaseView{{Address: "10.0.0.5", MAC: "aa", Hostname: "pc-5", Until: "завтра"}, {Address: "10.0.0.7", MAC: "bb", Hostname: "printer", Until: "завтра"}},
		[]reservationView{{ID: 1, Label: "Принтер", MAC: "bb", IP: "10.0.0.7"}, {ID: 2, Label: "Камера", MAC: "cc", IP: "10.0.0.9", Waiting: true}},
	)
	if len(rows) != 3 {
		t.Fatalf("строк %d, ждали 3: %+v", len(rows), rows)
	}
	if rows[0].Pinned || rows[0].Label != "pc-5" || !rows[0].HasLease {
		t.Fatalf("аренда без закрепления: %+v", rows[0])
	}
	if !rows[1].Pinned || rows[1].ResID != 1 || rows[1].Label != "Принтер" || !rows[1].HasLease {
		t.Fatalf("аренда с закреплением: %+v", rows[1])
	}
	if !rows[2].Pinned || rows[2].ResID != 2 || rows[2].HasLease || !rows[2].Waiting {
		t.Fatalf("закрепление без аренды: %+v", rows[2])
	}
}

func TestDeviceKindFromUserAgent(t *testing.T) {
	cases := map[string][2]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)":          {"phone", "iOS"},
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)":                   {"tablet", "iPadOS"},
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) Mobile Safari":          {"phone", "Android"},
		"Mozilla/5.0 (Linux; Android 14; SM-X910) Safari":                 {"tablet", "Android"},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0":         {"laptop", "Windows"},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari":             {"laptop", "macOS"},
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Firefox/130.0": {"desktop", "Linux"},
		"curl/8.5": {"desktop", ""},
	}
	for ua, want := range cases {
		icon, os := deviceKind(ua)
		if icon != want[0] || os != want[1] {
			t.Errorf("%q → %s/%s, ждали %s/%s", ua, icon, os, want[0], want[1])
		}
	}
}
