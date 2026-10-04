package main

import (
	"os"
	"regexp"
	"testing"
)

func TestDiagHasNoBackgroundTimers(t *testing.T) {
	src, err := os.ReadFile("diag.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`time\.(Ticker|NewTicker|Tick|AfterFunc|After)\(|go func\(\) \{\s*for`)
	if m := forbidden.Find(src); m != nil {
		t.Fatalf("в diag.go найден источник фоновой активности: %s", m)
	}
	if probeParallel > 32 || probeCount > 10 || probeTimeout.Seconds() > 60 {
		t.Fatal("пределы пробы выше согласованных потолков")
	}
}
