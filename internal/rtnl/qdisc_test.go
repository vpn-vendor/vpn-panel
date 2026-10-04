package rtnl

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type tcQdisc struct {
	Kind string `json:"kind"`
	Dev  string `json:"dev"`
	Tins []struct {
		SentPackets uint32 `json:"sent_packets"`
		Drops       uint32 `json:"drops"`
		AvgDelayUs  uint32 `json:"avg_delay_us"`
		PeakDelayUs uint32 `json:"peak_delay_us"`
		TargetUs    uint32 `json:"target_us"`
		IntervalUs  uint32 `json:"interval_us"`
	} `json:"tins"`
}

func TestParseQdiscDumpAgainstTC(t *testing.T) {
	raw, err := os.ReadFile("testdata/qdiscdump.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
	qs, err := ParseQdiscDump(data)
	if err != nil {
		t.Fatal(err)
	}
	js, _ := os.ReadFile("testdata/qdisc.json")
	var ref []tcQdisc
	if err := json.Unmarshal(js, &ref); err != nil {
		t.Fatal(err)
	}
	links, _ := ParseDump(fixture(t))
	names := map[int]string{}
	for _, l := range links {
		names[l.Index] = l.Name
	}
	cakes := 0
	for _, q := range qs {
		if q.Kind != "cake" {
			continue
		}
		cakes++
		var r *tcQdisc
		for i := range ref {
			if ref[i].Kind == "cake" && ref[i].Dev == names[q.IfIndex] {
				r = &ref[i]
			}
		}
		if r == nil {
			t.Fatalf("очередь cake на %q (index %d) отсутствует в tc -j", names[q.IfIndex], q.IfIndex)
		}
		if len(q.Tins) != len(r.Tins) {
			t.Fatalf("%s: уровней %d, в tc -j %d", r.Dev, len(q.Tins), len(r.Tins))
		}
		for i, tin := range q.Tins {
			rt := r.Tins[i]
			diff := int64(tin.SentPackets) - int64(rt.SentPackets)
			if diff < 0 {
				diff = -diff
			}
			if tin.TargetUs == 0 || tin.TargetUs != rt.TargetUs || tin.IntervalUs != rt.IntervalUs {
				t.Fatalf("%s tin %d: цель и интервал уровня разобраны как %d/%d, tc -j даёт %d/%d", r.Dev, i, tin.TargetUs, tin.IntervalUs, rt.TargetUs, rt.IntervalUs)
			}
			if diff > 50 || tin.DroppedPackets != rt.Drops || tin.PeakDelayUs != rt.PeakDelayUs {
				t.Fatalf("%s tin %d: разбор %+v, tc -j %+v", r.Dev, i, tin, rt)
			}
		}
	}
	if cakes < 3 {
		t.Fatalf("очередей cake разобрано %d — в образце их четыре", cakes)
	}
}

func TestNonCakeHasNoTins(t *testing.T) {
	raw, _ := os.ReadFile("testdata/qdiscdump.hex")
	data, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
	qs, _ := ParseQdiscDump(data)
	for _, q := range qs {
		if q.Kind != "cake" && len(q.Tins) != 0 {
			t.Fatalf("%s с уровнями: %+v", q.Kind, q.Tins)
		}
	}
}

func TestLiveQdiscDumpNoPrivileges(t *testing.T) {
	if _, err := DumpQdiscs(); err != nil {
		t.Skipf("дамп очередей недоступен здесь: %v", err)
	}
}
