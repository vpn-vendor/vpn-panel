package settings

import (
	"slices"
	"testing"
)

type sectionT struct {
	On      bool              `json:"on" setting:"qos.enabled"`
	Kbit    int               `json:"kbit" setting:"qos.down_kbit"`
	Master  string            `json:"master" setting:"metrics.master"`
	Sources map[string]string `json:"sources" setting:"metrics.source."`
	Free    string            `json:"free"`
}

func TestChanges(t *testing.T) {
	cur := sectionT{On: true, Kbit: 1000, Master: "on", Sources: map[string]string{"a": "on", "b": "off"}, Free: "x"}
	want := sectionT{On: false, Kbit: 1000, Master: "on", Sources: map[string]string{"a": "memory", "c": "on"}, Free: "y"}
	set, del, err := Changes(cur, want)
	if err != nil {
		t.Fatal(err)
	}
	wantSet := map[string]string{"qos.enabled": "0", "metrics.source.a": "memory", "metrics.source.c": "on"}
	if len(set) != len(wantSet) {
		t.Fatalf("пишется %v, ждали %v", set, wantSet)
	}
	for k, v := range wantSet {
		if set[k] != v {
			t.Errorf("%s = %q, ждали %q", k, set[k], v)
		}
	}
	if !slices.Equal(del, []string{"metrics.source.b"}) {
		t.Errorf("удаляется %v", del)
	}
	if s, d, _ := Changes(cur, cur); len(s) != 0 || len(d) != 0 {
		t.Errorf("без изменений пишется %v, удаляется %v", s, d)
	}
}

func TestChangesRejectsMismatch(t *testing.T) {
	if _, _, err := Changes(sectionT{}, struct{}{}); err == nil {
		t.Fatal("разные разделы приняты")
	}
}
