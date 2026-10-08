package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
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
		for _, want := range []string{"<h1 class=\"wizard-question\">" + template.HTMLEscapeString(step.Question), "class=\"stepper\"", "Перейти в панель", "</footer>"} {
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
