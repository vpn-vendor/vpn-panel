package backup

import (
	"encoding/json"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

type card struct {
	Name string `json:"name" ref:"nic"`
	MAC  string `json:"mac" ref:"mac"`
	Role string `json:"role"`
}

type sectionNet struct {
	Cards []card `json:"cards" table:"rows"`
}

func netDoc(t *testing.T, cards ...card) ([]Entry, *backupfile.Document) {
	t.Helper()
	raw, _ := json.Marshal(sectionNet{Cards: cards})
	doc := &backupfile.Document{Kind: backupfile.KindCopy, Sections: map[string]backupfile.Section{"net": {Version: 1, Data: raw}}}
	return []Entry{Of(Def[sectionNet]{Name: "net", Version: 1})}, doc
}

func TestMatchByMACOnly(t *testing.T) {
	entries, doc := netDoc(t, card{"enp1s0", "52:54:00:aa:00:01", "wan"}, card{"enp2s0", "52:54:00:aa:00:02", "lan"})
	refs, err := Refs(entries, doc)
	if err != nil || len(refs) != 2 || refs[0].Field("role") != "wan" {
		t.Fatalf("%v %+v", err, refs)
	}
	here := []Card{{"eth0", "52:54:00:AA:00:01"}, {"enp2s0", "52:54:00:bb:00:09"}}
	auto, ask := Match(refs, here)
	if auto["enp1s0"].Name != "eth0" || len(ask) != 1 || ask[0].Card.Name != "enp2s0" {
		t.Fatalf("auto=%v ask=%+v", auto, ask)
	}
	if _, errs := Assign(refs, here, nil); len(errs) != 1 {
		t.Fatalf("без выбора — ошибка: %v", errs)
	}
	if _, errs := Assign(refs, here, map[string]string{"enp2s0": "eth0"}); len(errs) != 1 {
		t.Fatalf("карта с двумя ролями — ошибка: %v", errs)
	}
	to, errs := Assign(refs, here, map[string]string{"enp2s0": "enp2s0"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := Remap(entries, doc, to); err != nil {
		t.Fatal(err)
	}
	var got sectionNet
	_ = json.Unmarshal(doc.Sections["net"].Data, &got)
	want := []card{{"eth0", "52:54:00:AA:00:01", "wan"}, {"enp2s0", "52:54:00:bb:00:09", "lan"}}
	if len(got.Cards) != 2 || got.Cards[0] != want[0] || got.Cards[1] != want[1] {
		t.Fatalf("переназначено: %+v", got.Cards)
	}
}
