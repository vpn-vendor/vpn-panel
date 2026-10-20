package controllers

import (
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagnose"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

func yes(id, level, cause, found string) hostcaps.Fact {
	return hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: hostcaps.Yes, Level: level, Cause: cause,
		Found: found, Title: "Заголовок " + id}
}

func TestLegacyFoldsIntoOneNotice(t *testing.T) {
	st := hostcaps.Surroundings{TakenAt: "2026-10-19T12:00:00Z", Facts: []hostcaps.Fact{
		yes("legacy.gateway", hostcaps.LevelWarn, hostcaps.CauseLegacy, "Старый шлюз."),
		yes("surroundings.dhcp_host", hostcaps.LevelError, hostcaps.CauseLegacy, "Чужой DHCP."),
		yes("legacy.danger.sudo", hostcaps.LevelError, hostcaps.CauseLegacy, "Права."),
		yes("surroundings.tls_port", hostcaps.LevelError, "", "Порт."),
		{ID: "legacy.pppoe", Class: hostcaps.ClassForeign, Answer: hostcaps.No},
	}}
	n := surroundNotices(st)
	if len(n) != 2 {
		t.Fatalf("ждали две плашки — опасное и старый шлюз: %+v", n)
	}
	if n[0].Level != "error" || n[0].Text != "Права." {
		t.Fatalf("опасное — отдельной плашкой первым: %+v", n[0])
	}
	if n[1].Level != "error" || !strings.HasPrefix(n[1].Text, "Старый шлюз.") || !strings.Contains(n[1].Text, "1 находка") {
		t.Fatalf("старый шлюз — одна плашка с уровнем самого тяжёлого: %+v", n[1])
	}
}

func TestSettlingShowsNoNotices(t *testing.T) {
	if n := surroundNotices(hostcaps.Surroundings{Settling: true}); len(n) != 0 {
		t.Fatalf("пока шлюз проверяет, тревожить нечем: %+v", n)
	}
}

func TestSurroundFactsFoldClean(t *testing.T) {
	st := hostcaps.Surroundings{TakenAt: "2026-10-19T12:00:00Z", Facts: []hostcaps.Fact{
		{ID: "surroundings.http_port", Class: hostcaps.ClassForeign, Answer: hostcaps.No},
		{ID: "legacy.pppoe", Class: hostcaps.ClassForeign, Answer: hostcaps.No},
		{ID: "legacy.running", Class: hostcaps.ClassForeign, Answer: hostcaps.Unknown, Title: "Старый скрипт работает"},
		yes("legacy.gateway", hostcaps.LevelWarn, hostcaps.CauseLegacy, "Старый шлюз."),
	}}
	st.Facts[3].Value = "vpn"
	got := surroundFacts(st, false, time.Now())
	labels := []string{}
	for _, it := range got.Items {
		labels = append(labels, it.Label+"="+it.Shown())
	}
	want := "Заголовок legacy.gateway=режим VPN|Старый скрипт работает=не удалось проверить|Остальное=не найдено|Проверено="
	if !strings.HasPrefix(strings.Join(labels, "|"), want) {
		t.Fatalf("строки блока: %v", labels)
	}
	if got.Items[0].Judged.Level() != ui.Warn {
		t.Fatalf("уровень найденного: %+v", got.Items[0])
	}
}

func TestHTTPPortNeedsBusyLAN(t *testing.T) {
	f := yes("surroundings.http_port", hostcaps.LevelWarn, "", "Порт 80 занят.")
	f.Value = "Apache"
	st := hostcaps.Surroundings{Facts: []hostcaps.Fact{f}}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	lan := map[string]time.Time{"192.168.11.1": now.Add(-time.Hour), "127.0.0.1": now.Add(-time.Hour)}
	if n := surroundNotices(withOwnBinding(st, lan, now)); len(n) != 1 || n[0].Level != "warn" {
		t.Fatalf("занят адрес офиса — плашка: %+v", n)
	}
	local := map[string]time.Time{"127.0.0.1": now.Add(-time.Hour)}
	if n := surroundNotices(withOwnBinding(st, local, now)); len(n) != 0 {
		t.Fatalf("занят только 127.0.0.1 — без плашки: %+v", n)
	}
	race := map[string]time.Time{"192.168.11.1": now.Add(-time.Second)}
	if n := surroundNotices(withOwnBinding(st, race, now)); len(n) != 0 {
		t.Fatalf("гонка при загрузке — не обстановка: %+v", n)
	}
}

func TestHTTPPortYoungRace(t *testing.T) {
	f := yes("surroundings.http_port", hostcaps.LevelWarn, "", "Порт 80 занят программой Apache.")
	f.Value = "Apache"
	st := hostcaps.Surroundings{Facts: []hostcaps.Fact{f}}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	race := map[string]time.Time{"192.168.11.1": now.Add(-time.Second), "127.0.0.1": now.Add(-time.Hour)}
	got := withOwnBinding(st, race, now).Facts[0]
	if got.Level != hostcaps.LevelInfo || strings.Contains(got.Found, "не мешает") || strings.Contains(got.Found, "работает") {
		t.Fatalf("в гонке после старта: %+v", got)
	}
}

func TestHoldSeenKeepsNotices(t *testing.T) {
	seen := map[string]system.SeenFact{
		"legacy.danger.sudo": {Answer: "yes", Level: hostcaps.LevelError, Cause: hostcaps.CauseLegacy,
			Title: "Права веб-сервера", Found: "Права.", At: "2026-10-19T10:00:00Z"},
		"legacy.pppoe": {Answer: "no"},
	}
	st := holdSeen(hostcaps.Surroundings{Settling: true}, seen)
	n := surroundNotices(st)
	if len(n) != 1 || n[0].Level != "error" || !strings.Contains(n[0].Text, "перепроверяет") {
		t.Fatalf("плашка держится с пометкой: %+v", n)
	}
	if got := holdSeen(hostcaps.Surroundings{Facts: []hostcaps.Fact{{ID: "x"}}}, seen); len(got.Facts) != 1 {
		t.Fatal("со свежим снимком отметка не нужна")
	}
}

func unknown(id, found string) hostcaps.Fact {
	return hostcaps.Fact{ID: id, Class: hostcaps.ClassForeign, Answer: hostcaps.Unknown, Title: "Заголовок " + id, Found: found}
}

func TestOfficeCutNotices(t *testing.T) {
	gw := yes("legacy.gateway", hostcaps.LevelWarn, hostcaps.CauseLegacy, "Старый шлюз.")
	cases := []struct {
		name  string
		facts []hostcaps.Fact
		want  []string
	}{
		{"срез от старого скрипта отдельно", []hostcaps.Fact{gw,
			yes("surroundings.forward_cut", hostcaps.LevelError, hostcaps.CauseLegacy, "Режет.")},
			[]string{"error:Режет.", "warn:Старый шлюз."}},
		{"источник жив — в сводную", []hostcaps.Fact{gw,
			yes("surroundings.forward_cut", hostcaps.LevelWarn, hostcaps.CauseLegacy, "Вернётся.")},
			[]string{"warn:Старый шлюз. Ещё 1 находка от старого скрипта — подробности в «Диагностике»."}},
		{"пересылка выключена", []hostcaps.Fact{
			yes("surroundings.forward_off", hostcaps.LevelError, "", "Выключена.")},
			[]string{"error:Выключена."}},
		{"чужой DHCP и стёртые правила не сводятся", []hostcaps.Fact{gw,
			yes("surroundings.dhcp_lan", hostcaps.LevelWarn, "", "Второй сервер."),
			yes("surroundings.own_table", hostcaps.LevelError, hostcaps.CauseLegacy, "Стёрли.")},
			[]string{"warn:Старый шлюз.", "warn:Второй сервер.", "error:Стёрли."}},
		{"сведение без плашки", []hostcaps.Fact{
			yes("surroundings.forward_cut", hostcaps.LevelInfo, "", "Правила есть.")}, nil},

		{"неизвестно", []hostcaps.Fact{unknown("surroundings.forward_cut", "Нет трафика.")}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, n := range surroundNotices(hostcaps.Surroundings{Facts: c.facts}) {
			got = append(got, n.Level+":"+n.Text)
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: плашки %q, ждали %q", c.name, got, c.want)
		}
	}
}

func TestSurroundOrderNewFacts(t *testing.T) {
	cases := map[string]int{
		"legacy.gateway": 0, "surroundings.forward_cut": 1, "surroundings.forward_off": 1,
		"surroundings.own_table": 1, "legacy.danger.sudo": 1, "legacy.pppoe": 2, "surroundings.dhcp_lan": 3,
	}
	for id, want := range cases {
		if got := surroundOrder(id); got != want {
			t.Errorf("%s: порядок %d, ждали %d", id, got, want)
		}
	}
}

func TestUnknownShowsAgentReason(t *testing.T) {
	cases := []struct {
		fact hostcaps.Fact
		note string
	}{
		{unknown("surroundings.dhcp_lan", "Шлюз слушает сеть офиса заново."), "Шлюз слушает сеть офиса заново."},
		{unknown("surroundings.forward_cut", ""), "Шлюз проверит снова через минуту"},
	}
	for _, c := range cases {
		got := surroundFacts(hostcaps.Surroundings{TakenAt: "2026-10-19T12:00:00Z", Facts: []hostcaps.Fact{c.fact}}, false, time.Now())
		if got.Items[0].Note != c.note || got.Items[0].Shown() != "не удалось проверить" {
			t.Errorf("%s: %+v", c.fact.ID, got.Items[0])
		}
	}
}

func TestHoldSeenPerFact(t *testing.T) {
	seen := map[string]system.SeenFact{
		"surroundings.forward_cut": {Answer: "yes", Level: hostcaps.LevelError, Title: "Пересылка режется",
			Found: "Режет.", Value: "Docker", At: "2026-10-19T10:00:00Z"},
		"surroundings.dhcp_lan": {Answer: "yes", Level: hostcaps.LevelWarn, Found: "Второй сервер.", At: "2026-10-19T10:00:00Z"},
		"legacy.pppoe":          {Answer: "no"},
	}
	reset := unknown("surroundings.dhcp_lan", "Шлюз слушает сеть офиса заново.")
	reset.Reset = true
	cases := []struct {
		name   string
		st     hostcaps.Surroundings
		id     string
		answer string
		has    []string
		hasnt  string
	}{
		{"неизвестно держит найденное", hostcaps.Surroundings{Facts: []hostcaps.Fact{unknown("surroundings.forward_cut", "")}},
			"surroundings.forward_cut", "yes", []string{"Режет. Замечено 19.10.2026"}, ""},

		{"объяснённое неизвестно держит", hostcaps.Surroundings{Facts: []hostcaps.Fact{unknown("surroundings.dhcp_lan", "Шлюз слушает сеть офиса.")}},
			"surroundings.dhcp_lan", "yes", []string{"Второй сервер. Замечено", "перепроверяет это. Шлюз слушает сеть офиса."}, ""},

		{"сброс кнопкой не держит", hostcaps.Surroundings{Facts: []hostcaps.Fact{reset}},
			"surroundings.dhcp_lan", "unknown", []string{"Шлюз слушает сеть офиса заново."}, "Второй сервер."},
		{"после перезагрузки", hostcaps.Surroundings{Settling: true},
			"surroundings.dhcp_lan", "yes", []string{"после перезагрузки."}, ""},

		{"нет — значит нет", hostcaps.Surroundings{Facts: []hostcaps.Fact{{ID: "surroundings.forward_cut", Answer: hostcaps.No}}},
			"surroundings.forward_cut", "no", nil, "Режет."},
		{"свежее «да» не трогаем", hostcaps.Surroundings{Facts: []hostcaps.Fact{yes("surroundings.forward_cut", hostcaps.LevelError, "", "Сейчас.")}},
			"surroundings.forward_cut", "yes", []string{"Сейчас."}, "Режет."},
		{"без перепроверки пропавшее не держим", hostcaps.Surroundings{}, "surroundings.dhcp_lan", "", nil, ""},
		{"было «нет» — держать нечего", hostcaps.Surroundings{Facts: []hostcaps.Fact{unknown("legacy.pppoe", "")}},
			"legacy.pppoe", "unknown", nil, ""},
	}
	for _, c := range cases {
		f, ok := holdSeen(c.st, seen).Fact(c.id)
		answer := ""
		if ok {
			answer = string(f.Answer)
		}
		if answer != c.answer {
			t.Errorf("%s: ответ %q, ждали %q (%q)", c.name, answer, c.answer, f.Found)
			continue
		}
		for _, part := range c.has {
			if !strings.Contains(f.Found, part) {
				t.Errorf("%s: в %q нет %q", c.name, f.Found, part)
			}
		}
		if c.hasnt != "" && strings.Contains(f.Found, c.hasnt) {
			t.Errorf("%s: в %q лишнее %q", c.name, f.Found, c.hasnt)
		}
	}
	held, _ := holdSeen(hostcaps.Surroundings{Facts: []hostcaps.Fact{unknown("surroundings.forward_cut", "")}}, seen).Fact("surroundings.forward_cut")
	if foundValue(held) != "Docker" {
		t.Fatalf("удержанный факт помнит виновника: %+v", held)
	}
}

func TestProviderNotes(t *testing.T) {
	gw := yes("legacy.gateway", hostcaps.LevelInfo, hostcaps.CauseLegacy, "Старый шлюз.")
	run := yes("legacy.running", hostcaps.LevelError, hostcaps.CauseLegacy, "Скрипт меняет систему.")
	cut := func(level string) hostcaps.Fact {
		return yes("surroundings.forward_cut", level, "", "Правила режут.")
	}
	cases := []struct {
		name    string
		st      hostcaps.Surroundings
		applied bool
		notes   []string
		network []string
	}{
		{"до ролей: ошибка", hostcaps.Surroundings{Facts: []hostcaps.Fact{cut(hostcaps.LevelError)}}, false,
			[]string{"warn:Правила режут."}, []string{"warn:Правила режут."}},
		{"до ролей: предупреждение", hostcaps.Surroundings{Facts: []hostcaps.Fact{cut(hostcaps.LevelWarn)}}, false,
			[]string{"warn:Правила режут."}, []string{"warn:Правила режут."}},
		{"до ролей: сведение тоже", hostcaps.Surroundings{Facts: []hostcaps.Fact{cut(hostcaps.LevelInfo), gw}}, false,
			[]string{"warn:Старый шлюз.", "warn:Правила режут."}, []string{"warn:Старый шлюз.", "warn:Правила режут."}},

		{"после ролей: срез не отсюда", hostcaps.Surroundings{Facts: []hostcaps.Fact{cut(hostcaps.LevelError)}}, true, nil, nil},
		{"после ролей: уровень у факта", hostcaps.Surroundings{Facts: []hostcaps.Fact{gw, run, cut(hostcaps.LevelWarn)}}, true,
			[]string{"info:Старый шлюз.", "error:Скрипт меняет систему."}, []string{"error:Скрипт меняет систему."}},
		{"«нет» молчит", hostcaps.Surroundings{Facts: []hostcaps.Fact{{ID: "surroundings.forward_cut", Answer: hostcaps.No, Found: "Не режет."}}}, false,
			nil, nil},
		{"проверка идёт после ролей", hostcaps.Surroundings{Settling: true}, true,
			[]string{"info:Шлюз ещё проверяет, что работает на сервере. Если на нём стоит старый скрипт vpn.sh, это станет видно через минуту."}, nil},
	}
	flat := func(ns []notice) []string {
		var out []string
		for _, n := range ns {
			out = append(out, n.Level+":"+n.Text)
		}
		return out
	}
	for _, c := range cases {
		if got := flat(providerNotes(c.st, c.applied)); strings.Join(got, "|") != strings.Join(c.notes, "|") {
			t.Errorf("%s: мастер %q, ждали %q", c.name, got, c.notes)
		}
		if got := flat(networkNotices(c.st, c.applied)); strings.Join(got, "|") != strings.Join(c.network, "|") {
			t.Errorf("%s: «Сеть» %q, ждали %q", c.name, got, c.network)
		}
	}
}

func TestLANLeaseNote(t *testing.T) {
	cases := []struct {
		name  string
		prep  func(f *setup.Facts)
		wants string
	}{
		{"карта офиса с арендой", func(f *setup.Facts) { f.Cards[1].DHCPServer = "192.168.1.1" },
			"Карта офиса «ens3» уже получила адрес от другого устройства в сети (192.168.1.1)"},
		{"черновик карты офиса", func(f *setup.Facts) { f.LANDraft = "ens3"; f.Cards[1].DHCPServer = "10.0.0.1" }, "(10.0.0.1)"},

		{"аренда только у карты в интернет", func(f *setup.Facts) { f.Cards[0].DHCPServer = "192.168.122.1" }, ""},
		{"роли уже применены", func(f *setup.Facts) { f.Cards[1].DHCPServer = "192.168.1.1"; f.RolesApplied = true }, ""},
		{"аренды нет", func(f *setup.Facts) {}, ""},
	}
	for _, c := range cases {
		f := sampleSetupFacts()
		f.WANDraft = "ens2"
		c.prep(&f)
		got := lanLeaseNote(f)
		if (c.wants == "") != (got == "") || !strings.Contains(got, c.wants) {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

func TestInternetStepOffice(t *testing.T) {
	cut := yes("surroundings.forward_cut", hostcaps.LevelError, "", "Docker режет трафик офиса.")
	const generic = "Шлюз увидит это, когда компьютеры офиса начнут выходить в интернет."
	cases := []struct {
		name     string
		prep     func(f *setup.Facts)
		value    string
		level    ui.Level
		note     string
		question string
		summary  string
	}{
		{"офис отрезан", func(f *setup.Facts) { f.Internet = "up"; f.OfficeCut = &cut }, "не проходит", ui.Bad, cut.Found,
			"У шлюза интернет есть, а у офиса нет", "у шлюза есть, офис отрезан"},
		{"офис проходит", func(f *setup.Facts) { f.Internet = "up"; f.OfficeOK = true }, "проходит", ui.OK, "", "", "работает"},

		{"проходит, а у шлюза интернета нет", func(f *setup.Facts) { f.Internet = "down"; f.OfficeOK = true },
			"ждёт интернета у шлюза", ui.None, "", "", "не отвечает"},
		{"проходит, а интернет у шлюза ещё не известен", func(f *setup.Facts) { f.OfficeOK = true },
			"ждёт интернета у шлюза", ui.None, "", "", "ещё проверяется"},
		{"трафика офиса ещё не было", func(f *setup.Facts) { f.Internet = "up" }, "проверяется", ui.None, generic, "", "работает"},
		{"агент объяснил, почему не знает", func(f *setup.Facts) {
			f.Internet = "up"
			f.OfficeWhy = "Защита офиса в аварийном режиме."
		}, "проверяется", ui.None, "Защита офиса в аварийном режиме.", "", "работает"},
		{"у шлюза интернета нет", func(f *setup.Facts) { f.Internet = "down"; f.OfficeCut = &cut }, "не проходит", ui.Bad, cut.Found, "", "офис отрезан"},
	}
	c := NewSetupController()
	step, _ := wizard.ByKey("internet")
	for _, tc := range cases {
		f := sampleSetupFacts()
		f.RolesApplied, f.WANName, f.LANName = true, "ens2", "ens3"
		tc.prep(&f)
		view := map[string]any{"step": step}
		c.fillInternet(f, view)
		var row ui.Fact
		for _, it := range view["facts"].(ui.Facts).Items {
			if it.Label == "Интернет в офисе" {
				row = it
			}
		}
		if row.Value != tc.value || row.Judged.Level() != tc.level {
			t.Errorf("%s: строка %+v", tc.name, row)
		}
		if tc.note != "" && !strings.Contains(row.Note, tc.note) {
			t.Errorf("%s: подсказка строки %q", tc.name, row.Note)
		}
		if tc.note != "" && tc.note != generic && strings.Contains(row.Note, generic) {
			t.Errorf("%s: общая подсказка вместо объяснения: %q", tc.name, row.Note)
		}
		q := view["step"].(wizard.Step).Question
		if (tc.question == "" && q != step.Question) || (tc.question != "" && q != tc.question) {
			t.Errorf("%s: вопрос %q", tc.name, q)
		}
		if tc.question != "" && view["step"].(wizard.Step).Hint != cut.Found {
			t.Errorf("%s: подсказка %q", tc.name, view["step"].(wizard.Step).Hint)
		}
		for _, it := range c.summary(f).Items {
			if it.Label == "Интернет" && it.Value != tc.summary {
				t.Errorf("%s: итог %q, ждали %q", tc.name, it.Value, tc.summary)
			}
		}
	}
}

func TestWithLanDHCP(t *testing.T) {
	report := &diagnose.Report{Level: diagnose.LevelInfo, Devices: []diagnose.Device{
		{MAC: "aa", IP: "192.168.11.5", Level: diagnose.LevelOK},
		{MAC: "bb", IP: "192.168.11.150", Level: diagnose.LevelInfo, Diagnoses: []diagnose.Diagnosis{
			{Code: "unknown_lease", Level: diagnose.LevelInfo}}},
	}}
	rows := []diag.Row{{Device: report.Devices[0]}, {Device: report.Devices[1]}}
	rows[0].Record.Label, rows[1].Record.Label = "Бухгалтерия", "Принтер"
	lan := yes("surroundings.dhcp_lan", hostcaps.LevelWarn, "", "Второй сервер.")
	lan.Value = "192.168.1.1, 192.168.1.2"
	r, got := withLanDHCP(report, rows, hostcaps.Surroundings{Facts: []hostcaps.Fact{lan}})
	if r.Level != diagnose.LevelWarn || got[0].MAC != "bb" || got[0].Record.Label != "Принтер" || got[1].Record.Label != "Бухгалтерия" {
		t.Fatalf("поправка: %s, %+v", r.Level, got)
	}
	if !strings.Contains(got[0].Diagnoses[0].Title, "(192.168.1.1, 192.168.1.2)") {
		t.Fatalf("адреса серверов: %s", got[0].Diagnoses[0].Title)
	}

	lan.Answer = hostcaps.Unknown
	if r, got := withLanDHCP(report, rows, hostcaps.Surroundings{Facts: []hostcaps.Fact{lan}}); r != report || got[0].MAC != "aa" {
		t.Fatal("без свежего второго сервера диагнозы не меняются")
	}
}
