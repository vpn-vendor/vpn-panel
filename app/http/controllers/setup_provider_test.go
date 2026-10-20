package controllers

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
)

func TestProviderGuess(t *testing.T) {
	cases := []struct {
		name  string
		card  setup.Card
		judge bool
		want  string
	}{
		{"кабеля нет", setup.Card{}, true, guessUnknown},
		{"роли уже применены", setup.Card{Up: true, HasRoute: true}, false, guessUnknown},
		{"маршрут через карту", setup.Card{Up: true, HasRoute: true}, true, guessAuto},
		{"адрес от провайдера", setup.Card{Up: true, Addresses: []string{"10.20.0.7/24"}}, true, guessAuto},
		{"только свой 169.254", setup.Card{Up: true, Addresses: []string{"169.254.3.9/16"}}, true, guessNone},
		{"кабель есть, адреса нет", setup.Card{Up: true}, true, guessNone},
	}
	for _, c := range cases {
		if got := providerGuess(c.card, c.judge); got != c.want {
			t.Errorf("%s: %q, ждали %q", c.name, got, c.want)
		}
	}
}

func TestMethodNotesCoverMethods(t *testing.T) {
	for _, g := range []string{guessUnknown, guessAuto, guessNone} {
		keys := map[string]bool{}
		for _, n := range methodNotes(g) {
			keys[n.Key] = true
			if n.Title == "" || n.Text == "" {
				t.Errorf("%q: пустое пояснение у %q", g, n.Key)
			}
		}
		for _, k := range []string{"dhcp", "pppoe", "static"} {
			if !keys[k] {
				t.Errorf("%q: нет пояснения к %q", g, k)
			}
		}
	}
	if methodNotes(guessAuto)[0].Level != ui.OK {
		t.Error("адрес пришёл сам — пояснение должно быть зелёным")
	}
	if methodNotes(guessNone)[0].Level == ui.OK {
		t.Error("адрес не пришёл — пояснение не может быть зелёным")
	}
}

func TestProviderDefaultFollowsGuess(t *testing.T) {
	c := NewSetupController()
	for _, tc := range []struct {
		addr bool
		want string
	}{{true, "dhcp"}, {false, "pppoe"}} {
		f := sampleSetupFacts()
		f.WANDraft = "ens2"
		if !tc.addr {
			f.Cards[0].Addresses, f.Cards[0].HasRoute = nil, false
		}
		view := map[string]any{"step": mustStep(t, "provider")}
		c.fillProvider(nil, f, view)
		got := ""
		for _, o := range view["choice"].(ui.Choice).Options {
			if o.Checked {
				got = o.Value
			}
		}
		if got != tc.want {
			t.Errorf("адрес пришёл=%v: отмечен %q, ждали %q", tc.addr, got, tc.want)
		}
	}
}

func mustStep(t *testing.T, key string) wizard.Step {
	t.Helper()
	s, ok := wizard.ByKey(key)
	if !ok {
		t.Fatalf("нет шага %q", key)
	}
	return s
}
