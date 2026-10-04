package vpndriver

import (
	"strings"
	"testing"
)

func TestUniqueSlugAlwaysAcceptedByAgent(t *testing.T) {
	names := []string{
		"Офис", "Германия Франкфурт резервный сервер", strings.Repeat("я", 80),
		"a", "---", "Server-01 (backup)", strings.Repeat("x-", 30),
	}
	for _, name := range names {
		base := Slug(name)
		taken := map[string]bool{}
		for n := 0; n < 120; n++ {
			s := UniqueSlug(base, func(v string) bool { return taken[v] })
			if !ValidSlug(s) {
				t.Fatalf("%q, занято %d: имя %q агент отвергнет", name, n, s)
			}
			if taken[s] {
				t.Fatalf("%q, занято %d: выдано занятое имя %q", name, n, s)
			}
			taken[s] = true
		}
	}
}

func TestUniqueSlugKeepsFreeBase(t *testing.T) {
	if got := UniqueSlug("office", func(string) bool { return false }); got != "office" {
		t.Fatalf("свободное имя изменено: %q", got)
	}
	long := Slug("Германия Франкфурт резервный сервер")
	got := UniqueSlug(long, func(v string) bool { return v == long })
	if got != "germaniya-frankfurt-re-2" {
		t.Fatalf("второе длинное имя: %q", got)
	}
}
