package controllers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
)

func TestWaitViewFollowsWatch(t *testing.T) {
	w := waitView(network.WatchView{State: network.WatchWaiting, Method: "dhcp", Left: 95, Total: 120}, false, "")
	if w.Big != "1:35" || w.Dash != 79 || w.Tone() != "run" {
		t.Errorf("ожидание: %q, %d, %q", w.Big, w.Dash, w.Tone())
	}
	if !strings.Contains(w.Lead, "за 2 минуты,") {
		t.Errorf("срок отката человеку: %q", w.Lead)
	}
	states := func(w []string) string { return strings.Join(w, ",") }
	got := func(v network.WatchView, internet bool) string {
		var s []string
		for _, c := range waitView(v, internet, "").Checks {
			s = append(s, c.State)
		}
		return states(s)
	}
	if g := got(network.WatchView{State: network.WatchWaiting}, true); g != "done,done,now,todo" {
		t.Errorf("ожидание: %s", g)
	}
	if g := got(network.WatchView{State: network.WatchConfirmed}, false); g != "done,done,done,now" {
		t.Errorf("закреплено, интернет ещё не ответил: %s", g)
	}
	if g := got(network.WatchView{State: network.WatchConfirmed}, true); g != "done,done,done,done" {
		t.Errorf("закреплено и интернет есть: %s", g)
	}
	if g := got(network.WatchView{State: network.WatchRolledBack}, false); g != "done,done,fail,todo" {
		t.Errorf("откат: %s", g)
	}
	back := waitView(network.WatchView{State: network.WatchRolledBack, Method: "pppoe"}, false, "")
	if back.Tone() != "warn" || !strings.Contains(back.Checks[2].Desc, "логин и пароль") {
		t.Errorf("откат с PPPoE: %q / %q", back.Tone(), back.Checks[2].Desc)
	}
}

func TestApplyingRenders(t *testing.T) {
	c := NewSetupController()
	tpl := wizardPages(t)
	f := sampleSetupFacts()
	f.WANDraft = "ens2"
	step, _ := wizard.ByKey("provider")
	for _, st := range []string{network.WatchWaiting, network.WatchConfirmed, network.WatchRolledBack} {
		w := waitView(network.WatchView{State: st, Method: "dhcp", Left: 60, Total: 120}, false, "window")
		step.Question, step.Hint = w.Title, w.Lead
		view := map[string]any{"csrf": "t", "static": "/public", "version": "v", "title": "т", "step": step,
			"stepper": stepperOf(wizard.Plan(f.Wizard())), "back": "", "error": "", "ok": "", "agentDown": false}
		c.fill(nil, "applying", f, view)
		view["wait"] = w
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "setup/applying", view); err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		out := buf.String()
		if strings.Contains(out, "style=") || strings.Contains(out, " onclick=") {
			t.Errorf("%s: инлайновый стиль или обработчик", st)
		}
		if strings.Contains(out, `id="keep-form"`) != (st == network.WatchWaiting) {
			t.Errorf("%s: форма «Оставить всё равно» не к месту", st)
		}
		if !strings.Contains(out, w.Title) || strings.Count(out, "data-wait-ring") != 2 {
			t.Errorf("%s: нет заголовка или кольца", st)
		}
	}
}

func TestWaitViewTakeoverRow(t *testing.T) {
	find := func(w ui.Wait) *ui.WaitCheck {
		for i := range w.Checks {
			if w.Checks[i].Key == "takeover" {
				return &w.Checks[i]
			}
		}
		return nil
	}
	if find(waitView(network.WatchView{State: network.WatchWaiting}, false, "")) != nil {
		t.Fatal("строка без захвата")
	}
	cases := []struct{ state, takeover, want string }{
		{network.WatchWaiting, "window", "todo"},
		{network.WatchWaiting, "consent", "todo"},
		{network.WatchConfirmed, "finishing", "now"},
		{network.WatchConfirmed, "done", "done"},
		{network.WatchConfirmed, "partial", "fail"},
		{network.WatchRolledBack, "consent", "todo"},
	}
	for _, tc := range cases {
		row := find(waitView(network.WatchView{State: tc.state}, false, tc.takeover))
		if row == nil || row.State != tc.want {
			t.Errorf("%s/%s: %+v, ждали %s", tc.state, tc.takeover, row, tc.want)
		}
	}
	back := waitView(network.WatchView{State: network.WatchRolledBack}, false, "consent")
	if !strings.Contains(back.Lead, "старый шлюз") || find(back).Title != "Старый шлюз снова работает" {
		t.Fatalf("откат с захватом: %q / %+v", back.Lead, find(back))
	}
}
