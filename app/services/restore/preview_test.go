package restore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
)

func ref(name, role string) backup.Ref {
	return backup.Ref{Card: backup.Card{Name: name}, Row: map[string]json.RawMessage{"role": json.RawMessage(`"` + role + `"`)}}
}

func TestCableHints(t *testing.T) {
	refs := []backup.Ref{ref("old-wan", "wan"), ref("old-lan", "lan")}
	to := map[string]backup.Card{"old-wan": {Name: "enp1s0"}, "old-lan": {Name: "enp2s0"}}

	cards := []CardFacts{{Card: backup.Card{Name: "enp1s0"}, Link: true}, {Card: backup.Card{Name: "enp2s0"}, Link: true, Provider: true}}
	h := cableHints(refs, to, cards)
	if len(h) != 1 || !strings.Contains(h[0], "интернет приходит в карту enp2s0") || !strings.Contains(h[0], "карту enp1s0") {
		t.Fatalf("перепутанный кабель: %v", h)
	}

	cards = []CardFacts{{Card: backup.Card{Name: "enp1s0"}}, {Card: backup.Card{Name: "enp2s0"}, Link: true}}
	if h := cableHints(refs, to, cards); len(h) != 1 || !strings.Contains(h[0], "нет кабеля") {
		t.Fatalf("нет кабеля: %v", h)
	}

	cards = []CardFacts{{Card: backup.Card{Name: "enp1s0"}, Link: true, Provider: true}, {Card: backup.Card{Name: "enp2s0"}, Link: true}}
	if h := cableHints(refs, to, cards); len(h) != 0 {
		t.Fatalf("лишняя подсказка: %v", h)
	}
}
