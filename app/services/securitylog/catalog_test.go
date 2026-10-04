package securitylog

import (
	"testing"
	"time"
)

func TestCatalogEntriesComplete(t *testing.T) {
	for code, e := range catalog {
		if e.Title == "" {
			t.Errorf("%s: нет названия", code)
		}
		switch e.Class {
		case Critical, Ordinary, System:
		default:
			t.Errorf("%s: неизвестный класс %q", code, e.Class)
		}

		if e.Failure && e.Class == Ordinary {
			t.Errorf("%s: отказ шлюза не может быть событием из сети", code)
		}
	}
	if Title("nonexistent_code") != UnknownTitle || ClassOf("nonexistent_code") != Critical {
		t.Fatal("код вне каталога: человеческое слово и критичный класс")
	}
}

func TestFailureCodes(t *testing.T) {
	got := map[string]bool{}
	for _, c := range FailureCodes() {
		got[c] = true
	}
	for _, c := range []string{"vpn_apply_failed", "network_rolled_back", "panel_crashed", "unclean_shutdown"} {
		if !got[c] {
			t.Errorf("%s обязан считаться отказом", c)
		}
	}
	for _, c := range []string{"vpn_import_failed", "code_failed", "path_tunnel_down"} {
		if got[c] {
			t.Errorf("%s не отказ шлюза", c)
		}
	}
}

func TestSystemCapShape(t *testing.T) {
	perDay := len(CodesOf(System)) * int(24*time.Hour/DedupWindow)
	if perDay == 0 || SystemCap(1) != perDay || SystemCap(7) != 7*perDay {
		t.Fatalf("потолок системных: %d в сутки, SystemCap(1)=%d, SystemCap(7)=%d", perDay, SystemCap(1), SystemCap(7))
	}
}
