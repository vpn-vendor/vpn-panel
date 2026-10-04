package controllers

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpncheck"
)

func TestPastCheckIsMarked(t *testing.T) {
	rep := &vpncheck.Report{Mode: "quick"}
	if vm := checkView(rep, true); !vm.Has || !vm.Past {
		t.Fatalf("прошлый отчёт: %+v", vm)
	}
	if vm := checkView(rep, false); vm.Past {
		t.Fatal("текущий отчёт помечен прошлым")
	}
}
