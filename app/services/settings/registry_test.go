package settings

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const root = "../../.."

func TestRegistryValid(t *testing.T) {
	for _, err := range Validate(Keys, Tables) {
		t.Error(err)
	}
}

func TestValidateRejects(t *testing.T) {
	for _, c := range []struct {
		name string
		key  Key
	}{
		{"секрет в базе", Key{Name: "vpn.private_key", Section: SectionVPN, Data: Secret, Risk: Safe}},
		{"нет класса риска", Key{Name: "qos.x", Section: SectionQoS, Data: Policy}},
		{"нет класса данных", Key{Name: "qos.x", Section: SectionQoS, Risk: Safe}},
		{"нет раздела", Key{Name: "qos.x", Data: Policy, Risk: Safe}},
		{"опасная без причины", Key{Name: "dns.override", Section: SectionDNS, Data: Policy, Risk: Dangerous}},
		{"опасная без слов для человека", Key{Name: "dns.override", Section: SectionDNS, Data: Policy, Risk: Dangerous, Why: "подмена имён"}},
		{"машина без причины", Key{Name: "net.card", Section: SectionNetwork, Data: Machine, Risk: Safe}},
		{"опасное состояние", Key{Name: "diag.x", Section: SectionDiag, Data: State, Risk: Dangerous, Why: "—"}},
		{"начало без точки", Key{Name: "vpn.probe", Prefix: true, Section: SectionVPN, Data: Office, Risk: Safe}},
		{"без имени", Key{Section: SectionVPN, Data: Office, Risk: Safe}},
		{"хвост без владельца", Key{Name: "vpn.probe.", Prefix: true, Section: SectionVPN, Data: Office, Risk: Safe}},
		{"владелец без хвоста", Key{Name: "vpn.x", Owner: OwnerVPNProfile, Section: SectionVPN, Data: Office, Risk: Safe}},
		{"неизвестный владелец", Key{Name: "vpn.x.", Prefix: true, Owner: "туннель", Section: SectionVPN, Data: Office, Risk: Safe}},
		{"неизвестная ссылка", Key{Name: "vpn.x", RefersTo: "туннель", Section: SectionVPN, Data: Office, Risk: Safe}},
		{"ссылка у хвоста", Key{Name: "vpn.x.", Prefix: true, Owner: OwnerVPNProfile, RefersTo: OwnerVPNProfile, Section: SectionVPN, Data: Office, Risk: Safe}},
	} {
		if errs := Validate([]Key{c.key}, nil); len(errs) == 0 {
			t.Errorf("%s: реестр принят, ждали отказ", c.name)
		}
	}
	dup := Key{Name: "qos.x", Section: SectionQoS, Data: Policy, Risk: Safe}
	if errs := Validate([]Key{dup, dup}, nil); len(errs) == 0 {
		t.Error("повтор ключа принят")
	}
	if errs := Validate(nil, []Table{{Name: "t", Section: SectionVPN, Data: Secret, Risk: Safe}}); len(errs) == 0 {
		t.Error("таблица с секретами принята")
	}
	if errs := Validate(nil, []Table{{Name: "t", Section: SectionVPN, Data: Office, Risk: Safe, Owner: "туннель"}}); len(errs) == 0 {
		t.Error("таблица с неизвестным владельцем принята")
	}
	two := []Table{{Name: "t1", Section: SectionVPN, Data: Office, Risk: Safe, Owner: OwnerVPNProfile},
		{Name: "t2", Section: SectionVPN, Data: Office, Risk: Safe, Owner: OwnerVPNProfile}}
	if errs := Validate(nil, two); len(errs) == 0 {
		t.Error("две таблицы одного владельца приняты")
	}
}

func TestOwnedByProfile(t *testing.T) {
	drop, clear := Owned(Keys, OwnerVPNProfile, "opyt")
	if !slices.Equal(drop, []string{"vpn.probe_target.opyt"}) {
		t.Errorf("удаляются %v, ждали только цель пробы этого профиля", drop)
	}
	if !slices.Equal(clear, []string{"vpn.active_slug"}) {
		t.Errorf("очищаются %v, ждали выбор активного профиля", clear)
	}
	if d, c := Owned(Keys, OwnerVPNProfile, ""); d != nil || c != nil {
		t.Errorf("пустое имя задело %v %v", d, c)
	}
	for _, k := range Keys {
		if !k.Prefix {
			continue
		}
		d, _ := Owned(Keys, k.Owner, "x")
		if !slices.Contains(d, k.Name+"x") {
			t.Errorf("ключ %q не убирается вместе с владельцем", k.Name)
		}
	}
}

func TestTemplateLaw(t *testing.T) {
	for d := Policy; d <= State; d++ {
		for r := Safe; r <= Dangerous; r++ {
			in, consent := InTemplate(d, r), TemplateConsent(d, r)
			wantIn := d == Policy && r != Dangerous
			if in != wantIn {
				t.Errorf("данные %d, риск %d: в шаблоне %v, по закону %v", d, r, in, wantIn)
			}
			if consent != (wantIn && r == Notable) {
				t.Errorf("данные %d, риск %d: отметка человека %v", d, r, consent)
			}
			if in && !d.InCopy() {
				t.Errorf("данные %d в шаблоне, но не в копии", d)
			}
		}
	}
	if Secret.InCopy() != true || Machine.InCopy() || State.InCopy() {
		t.Error("копия: секрет — да, машина и состояние — нет")
	}
}

func goFiles(t *testing.T, dirs ...string) []string {
	t.Helper()
	var out []string
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

var keyConstRe = regexp.MustCompile(`(?m)^\s*(?:const\s+)?[Ss]etting[A-Za-z0-9_]*\s*=\s*"([^"]+)"`)

func TestEveryKeyConstantDeclared(t *testing.T) {
	found := 0
	for _, f := range goFiles(t, "app", "bootstrap") {
		data, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range keyConstRe.FindAllStringSubmatch(string(data), -1) {
			found++
			key := m[1]
			if strings.HasSuffix(key, ".") {
				ok := false
				for _, k := range Keys {
					ok = ok || (k.Prefix && k.Name == key)
				}
				if !ok {
					t.Errorf("%s: начало ключа %q не объявлено в реестре", f, key)
				}
				continue
			}
			if _, ok := Lookup(key); !ok {
				t.Errorf("%s: ключ %q не объявлен в реестре", f, key)
			}
		}
	}

	if found < 30 {
		t.Fatalf("страж нашёл лишь %d констант ключей — поиск сломан", found)
	}
}

var directRe = regexp.MustCompile(`models\.Setting\b|Table\("settings"\)|(?i)\b(?:from|into|update)\s+settings\b`)

func TestNoDirectTableAccess(t *testing.T) {
	for _, f := range goFiles(t, "app", "bootstrap", "cmd", "internal", "routes") {
		rel := filepath.ToSlash(f)
		if strings.Contains(rel, "/app/services/settings/") || strings.HasSuffix(rel, "/app/models/auth.go") {
			continue
		}
		data, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		if loc := directRe.FindIndex(data); loc != nil {
			t.Errorf("%s: обращение к таблице настроек мимо пакета settings: %q", f, data[loc[0]:loc[1]])
		}
	}
}

var (
	createRe    = regexp.MustCompile(`Schema\(\)\.Create\("([a-z0-9_]+)"`)
	tableNameRe = regexp.MustCompile(`TableName\(\) string \{ return "([a-z0-9_]+)" \}`)
)

func TestEveryTableClassified(t *testing.T) {
	names := map[string]bool{"migrations": true}
	for _, dir := range []string{"database/migrations", "app/models"} {
		for _, f := range goFiles(t, dir) {
			data, err := os.ReadFile(f) //nolint:gosec
			if err != nil {
				t.Fatal(err)
			}
			for _, re := range []*regexp.Regexp{createRe, tableNameRe} {
				for _, m := range re.FindAllStringSubmatch(string(data), -1) {
					names[m[1]] = true
				}
			}
		}
	}
	declared := map[string]bool{}
	for _, tb := range Tables {
		declared[tb.Name] = true
	}
	var missing, stale []string
	for n := range names {
		if !declared[n] {
			missing = append(missing, n)
		}
	}
	for n := range declared {
		if !names[n] {
			stale = append(stale, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("таблицы без класса копии: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("в реестре таблицы, которых нет в базе: %v", stale)
	}
	if len(names) < 10 {
		t.Fatalf("страж нашёл лишь %d таблиц — поиск сломан", len(names))
	}
}

func TestEverySectionHasTitle(t *testing.T) {
	for _, k := range Keys {
		if _, ok := sectionTitles[k.Section]; !ok {
			t.Errorf("раздел %q без названия", k.Section)
		}
	}
	for _, tb := range Tables {
		if _, ok := sectionTitles[tb.Section]; !ok && tb.Data.InCopy() {
			t.Errorf("раздел %q без названия", tb.Section)
		}
	}
}
