package navigation

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/help"
)

func TestEverySectionFindsItselfFirst(t *testing.T) {
	for _, s := range Sections() {
		got := Search(s.Title)
		if len(got) == 0 || got[0].URL != s.URL {
			t.Fatalf("раздел «%s» не нашёлся первым по своему названию: %+v", s.Title, got)
		}
	}
}

func TestTermsFindTheirPages(t *testing.T) {
	cases := map[string]string{
		"dns":        "/dns",
		"имя панели": "/dns",
		"pppoe":      "/network",
		"vlan":       "/network",
		"mtu":        "/vpn",
		"openvpn":    "/vpn",
		"скорость":   "/qos",
		"журнал":     "/devices",
		"код входа":  "/devices",
		"аренды":     "/dhcp",
	}
	for q, want := range cases {
		got := Search(q)
		if len(got) == 0 {
			t.Fatalf("по «%s» не нашлось ничего, ждали %s", q, want)
		}
		if got[0].URL != want {
			t.Fatalf("по «%s» первым стоит %s, ждали %s", q, got[0].URL, want)
		}
	}
}

func TestYoIsE(t *testing.T) {
	if got := Search("защищенный"); len(got) == 0 {
		t.Fatalf("«защищенный» без ё не нашёл «Защищённый»")
	}
}

func TestAllWordsMustMatch(t *testing.T) {
	for _, e := range Search("скорость тарифа") {
		text := normalize(e.Title + " " + e.Hint + " " + strings.Join(e.Keywords, " "))
		if !strings.Contains(text, "скорость") || !strings.Contains(text, "тариф") {
			t.Fatalf("в выдаче запись без одного из слов: %+v", e)
		}
	}
}

func TestEmptyQueryFindsNothing(t *testing.T) {
	for _, q := range []string{"", "   ", "\t\n"} {
		if got := Search(q); got != nil {
			t.Fatalf("пустой запрос %q что-то нашёл: %+v", q, got)
		}
	}
}

func TestSearchIsBounded(t *testing.T) {
	huge := strings.Repeat("а", 100000)
	if got := Search(huge); len(got) > MaxResults {
		t.Fatalf("выдача больше потолка: %d", len(got))
	}
	for _, q := range []string{"<script>", "' OR 1=1 --", "\x00\x01", "../../etc/passwd"} {
		if got := Search(q); len(got) > MaxResults {
			t.Fatalf("выдача больше потолка на %q", q)
		}
	}

	if got := Search("а"); len(got) > MaxResults {
		t.Fatalf("выдача на одну букву больше потолка: %d", len(got))
	}
}

func TestEntriesPointToRealSections(t *testing.T) {
	for _, e := range entries {
		s, ok := SectionByKey(e.Section)
		if !ok {
			t.Fatalf("настройка «%s» ссылается на несуществующий раздел %q", e.Title, e.Section)
		}
		if e.URL != s.URL {
			t.Fatalf("настройка «%s» ведёт на %s, а её раздел живёт на %s", e.Title, e.URL, s.URL)
		}
	}
}

func TestSectionsAreUnique(t *testing.T) {
	keys, urls := map[string]bool{}, map[string]bool{}
	for _, s := range Sections() {
		if keys[s.Key] || urls[s.URL] {
			t.Fatalf("раздел повторяется: %+v", s)
		}
		keys[s.Key], urls[s.URL] = true, true
		if s.Title == "" || s.Subtitle == "" || s.Icon == "" {
			t.Fatalf("у раздела не заполнено название, пояснение или значок: %+v", s)
		}
	}
}

func TestSectionTitlesFollowDictionary(t *testing.T) {
	banned := []string{"Выдача адресов", "Имена в сети", "Приоритет трафика", "Защищённый канал"}
	for _, s := range Sections() {
		for _, b := range banned {
			if s.Title == b {
				t.Fatalf("раздел назван переводом термина: %q", s.Title)
			}
		}
	}
}

func TestGroupsKeepEverySection(t *testing.T) {
	n := 0
	for _, g := range Groups() {
		n += len(g.Sections)
	}
	if n != len(Sections()) {
		t.Fatalf("в группах разделов %d, в меню %d", n, len(Sections()))
	}
}

func TestEverySectionDeclaresItsWidth(t *testing.T) {
	for _, s := range Sections() {
		if !s.Width.Valid() {
			t.Errorf("раздел %q без объявленной ширины листа", s.Key)
		}
	}
	if w := WidthFor("home"); w != Wide {
		t.Errorf("обзор обязан быть широким: %q", w)
	}

	if w := WidthFor("такого-раздела-нет"); w != Narrow {
		t.Errorf("страница вне реестра: %q", w)
	}
	if Width("").Valid() || Width("огромная").Valid() {
		t.Error("пустая и выдуманная ширина обязаны быть недействительными")
	}
}

func TestHelpTopicsPointAtRealSections(t *testing.T) {
	known := func(key string) bool { _, ok := SectionByKey(key); return ok }
	if err := help.Validate(help.Topics(), func(string) bool { return true }, known); err != nil {
		t.Fatal(err)
	}
	for _, topic := range help.Topics() {
		if topic.Section == "" {
			continue
		}
		section, _ := SectionByKey(topic.Section)
		if !strings.Contains(strings.Join(topic.Steps, " "), section.Title) {
			t.Errorf("тема «%s» ведёт в раздел «%s», но совет его не называет", topic.Question, section.Title)
		}
	}
}
