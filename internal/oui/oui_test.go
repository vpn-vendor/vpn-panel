package oui

import "testing"

func TestVendorKnownPrefixes(t *testing.T) {

	if !Randomized("52:54:00:12:34:10") {
		t.Fatal("52:54:00 имеет бит локального администрирования")
	}
	if v := Vendor("52:54:00:12:34:10"); v != "" {
		t.Fatalf("у случайного адреса производителя нет, получено %q", v)
	}

	if v := Vendor("00-1b-21-aa-bb-cc"); v == "" || !containsFold(v, "intel") {
		t.Fatalf("00:1B:21 → Intel, получено %q", v)
	}
	if Vendor("zz") != "" || Vendor("") != "" {
		t.Fatal("мусор → пустая строка")
	}
	if Updated() == "" {
		t.Fatal("дата обновления реестра обязана быть встроена")
	}
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
