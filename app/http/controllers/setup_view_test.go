package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

func wizardPages(t *testing.T) *template.Template {
	t.Helper()
	root := filepath.Join("..", "..", "..", "resources", "views")
	files := []string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "speedtest_card.tmpl")}
	steps, err := filepath.Glob(filepath.Join(root, "setup", "*.tmpl"))
	if err != nil || len(steps) == 0 {
		t.Fatalf("шаблоны шагов не найдены: %v", err)
	}
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append(append(files, steps...), atoms...)...)
	if err != nil {
		t.Fatalf("шаблоны мастера не разбираются: %v", err)
	}
	return tpl
}

func sampleSetupFacts() setup.Facts {
	return setup.Facts{
		HasAdmin: true,
		Cards: []setup.Card{
			{Name: "ens2", MAC: "52:54:00:00:00:02", Up: true, Addresses: []string{"192.168.122.5/24"}, HasRoute: true},
			{Name: "ens3", MAC: "52:54:00:00:00:03", Up: true},
		},
		Skipped: map[string]bool{},
	}
}

func TestEveryWizardStepRenders(t *testing.T) {
	c := NewSetupController()
	tpl := wizardPages(t)
	f := sampleSetupFacts()
	f.WANDraft, f.RolesApplied, f.WANName, f.LANName, f.LANCIDR = "ens2", true, "ens2", "ens3", "192.168.11.1/24"
	f.Takeover = setup.TakeoverFacts{Digest: "d", Items: []system.TakeoverItem{
		{ID: "legacy.pppoe", Title: "PPPoE старого скрипта", Found: "Остановится", Checked: true},
		{ID: "foreign.docker", Title: "Docker", Found: "Остаётся", Locked: true},
	}}
	f.Legacy = &legacyvpn.Settings{WAN: legacyvpn.WAN{Card: "ens2", Method: legacyvpn.MethodPPPoE, PPPoEUser: "office", PPPoEPassword: true},
		LAN: legacyvpn.LAN{Card: "ens3", CIDR: "192.168.11.1/24"}, VPN: &legacyvpn.VPN{Protocol: legacyvpn.ProtocolOpenVPN, Endpoint: "vpn.example.net:1194"},
		Missing: []legacyvpn.Missing{{What: "диапазон выдачи адресов", Why: "файла нет"}}}
	plan := wizard.Plan(f.Wizard())
	for _, step := range wizard.Steps() {
		view := map[string]any{"csrf": "t", "static": "/public", "version": "v0.3.2", "title": step.Title,
			"step": step, "stepper": stepperOf(plan), "back": "/setup/account", "error": "", "ok": "", "agentDown": false}
		c.fill(nil, step.Key, f, view)
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "setup/"+step.Key, view); err != nil {
			t.Fatalf("шаг «%s» не отрисовался: %v", step.Key, err)
		}
		out := buf.String()

		shown := view["step"].(wizard.Step)
		for _, want := range []string{"<h1 class=\"wizard-question\">" + template.HTMLEscapeString(shown.Question), "class=\"wz-phases\"", "Настроить позже и открыть панель", "class=\"wz-foot\"", "</footer>"} {
			if !strings.Contains(out, want) {
				t.Errorf("шаг «%s»: на странице нет %q", step.Key, want)
			}
		}
		for _, forbidden := range []string{"style=\"", "onclick=", "onchange=", "onsubmit="} {
			if strings.Contains(out, forbidden) {
				t.Errorf("шаг «%s» принёс запрещённое %q", step.Key, forbidden)
			}
		}
	}
}

func TestWizardSuggestsAnswers(t *testing.T) {
	f := sampleSetupFacts()
	if got := f.SuggestWAN(); got != "ens2" {
		t.Fatalf("карта в интернет: %q, ждали ens2 (у неё маршрут)", got)
	}
	ch := cardChoice(f, f.SuggestWAN(), "")
	checked := 0
	for _, o := range ch.Options {
		if o.Checked {
			checked++
			if o.Value != "ens2" {
				t.Fatalf("отмечена не та карта: %s", o.Value)
			}
		}
	}
	if checked != 1 {
		t.Fatalf("отмечен ровно один вариант, а не %d", checked)
	}
	f.Cards[0].Addresses = []string{"192.168.11.7/24"}
	if got := f.SuggestLANCIDR(); got == "192.168.11.1/24" {
		t.Fatalf("адрес офиса совпал с сетью провайдера: %s", got)
	}
	if f.WANDraft = "ens2"; f.ChosenLAN() != "ens3" {
		t.Fatalf("с двумя картами вторая — офис, а не %q", f.ChosenLAN())
	}
}

func TestTakeoverListFollowsConsent(t *testing.T) {
	tf := setup.TakeoverFacts{Digest: "d", Items: []system.TakeoverItem{
		{ID: "legacy.pppoe", Title: "PPPoE", Checked: true},
		{ID: "foreign.netplan.x.yaml", Title: "Netplan", Checked: false},
		{ID: "foreign.docker", Title: "Docker", Locked: true},
	}}
	l := takeoverListOf(tf)
	if len(l.Items) != 3 || !l.Items[0].Checked || l.Items[1].Checked || !l.Items[2].Locked || l.Field(l.Items[0]) != "item_legacy.pppoe" {
		t.Fatalf("по плану: %+v", l.Items)
	}
	tf.Consent = &network.TakeoverConsent{Digest: "d", IDs: []string{"foreign.netplan.x.yaml"}}
	l = takeoverListOf(tf)
	if l.Items[0].Checked || !l.Items[1].Checked {
		t.Fatalf("по согласию: %+v", l.Items)
	}
	tf.Consent.Digest = "другой"
	if l = takeoverListOf(tf); !l.Items[0].Checked || l.Items[1].Checked || tf.Approved() {
		t.Fatalf("чужое согласие не в счёт: %+v", l.Items)
	}
	tpl := wizardPages(t)
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "components/takeover-list", takeoverListOf(tf)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "type=\"checkbox\"") != 2 || !strings.Contains(out, "choice-item-locked") || !strings.Contains(out, "name=\"item_legacy.pppoe\"") {
		t.Fatalf("разметка списка:\n%s", out)
	}
}

func TestLegacyPrefillsWizardSteps(t *testing.T) {
	c := NewSetupController()
	tpl := wizardPages(t)
	f := sampleSetupFacts()
	f.WANDraft, f.LANDraft = "ens2", "ens3"
	f.Legacy = &legacyvpn.Settings{WAN: legacyvpn.WAN{Card: "ens2", Method: legacyvpn.MethodPPPoE, PPPoEUser: "office@isp", PPPoEPassword: true},
		LAN: legacyvpn.LAN{Card: "ens3", CIDR: "192.168.11.1/24"}, VPN: &legacyvpn.VPN{Protocol: legacyvpn.ProtocolWireGuard, Endpoint: "vpn.example.net:51820"},
		Missing: []legacyvpn.Missing{{What: "диапазон выдачи адресов", Why: "файла нет"}}}
	render := func(key string) string {
		step, _ := wizard.ByKey(key)
		view := map[string]any{"csrf": "t", "static": "/public", "version": "v", "title": step.Title, "step": step,
			"stepper": stepperOf(wizard.Plan(f.Wizard())), "back": "", "error": "", "ok": "", "agentDown": false}
		c.fill(nil, key, f, view)
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "setup/"+key, view); err != nil {
			t.Fatalf("шаг %s: %v", key, err)
		}
		return buf.String()
	}
	out := render("takeover")
	for _, want := range []string{"Что возьмём у старого шлюза", "PPPoE с логином office@isp и паролем", "Не удалось прочитать", "диапазон выдачи адресов: файла нет"} {
		if !strings.Contains(out, want) {
			t.Errorf("шаг старого шлюза без %q", want)
		}
	}
	out = render("provider")
	for _, want := range []string{`value="office@isp"`, `name="pppoepass_source_ens2" value="legacy"`, "Пароль возьмём у старого шлюза", `value="pppoe"` + "\n" + `               checked`} {
		if !strings.Contains(out, want) {
			t.Errorf("шаг провайдера без %q", want)
		}
	}
	out = render("channel")
	for _, want := range []string{`name="source" value="legacy"`, `name="protocol" value="wireguard"`, "Взять подключение старого шлюза", "vpn.example.net:51820"} {
		if !strings.Contains(out, want) {
			t.Errorf("шаг канала без %q", want)
		}
	}
	f.Legacy = nil
	if out := render("channel"); strings.Contains(out, "legacy-form") {
		t.Error("кнопка старого шлюза без старого шлюза")
	}
	if out := render("provider"); strings.Contains(out, "pppoepass_source") {
		t.Error("источник пароля без старого шлюза")
	}
}
