package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/navigation"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	vpnsvc "github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpncheck"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

var profileInApply = regexp.MustCompile(`name="profile" value="fra"\s+form="vpn-apply"`)

func renderVPN(t *testing.T, view map[string]any) string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, _ := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	tpl, err := template.ParseFiles(append([]string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "vpn.tmpl")}, atoms...)...)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{"title": "VPN", "active": "vpn", "csrf": "tok", "static": "/public", "version": "", "searchQuery": "", "nav": navigation.Groups(), "pageWidth": string(navigation.WidthFor("vpn"))} {
		view[k] = v
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "vpn.tmpl", view); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func vpnTestView(settings vpnsvc.Settings, rows []profileView, st *vpnsvc.Status) map[string]any {
	view := map[string]any{"profiles": rows, "hasProfile": len(rows) > 0, "black": settings.Mode == vpnsvc.ModeBlack,
		"modeCards": vpnModeCards(settings.Mode == vpnsvc.ModeBlack, len(rows) > 0), "tunnelWord": tunnelWord, "tunnelMode": tunnelModeName(), "failCards": vpnFailCards(settings.OnFailure == vpnsvc.FailStrict),
		"dnsCards": vpnDNSCards(false, ""), "upload": uploadView(), "verdict": vpnVerdictKind(settings),
		"pathKnown": true, "findings": nil}
	var active *profileView
	for i := range rows {
		if rows[i].Active {
			active = &rows[i]
			view["activeName"] = rows[i].Name
		}
	}
	if active == nil && len(rows) > 0 {
		active = &rows[0]
	}
	f := vpnFacts{Black: settings.Mode == vpnsvc.ModeBlack, Strict: settings.OnFailure == vpnsvc.FailStrict, Active: active, Unknown: "служба молчит",
		NeverEnabled: settings.ActiveSlug == ""}
	link := vpnLink{}
	if st != nil {
		f.Status, f.Protocol, f.Transport, f.RxText, f.TxText = st, "WireGuard", "UDP", "4,2 ГБ", "610 МБ"
		link = vpnLink{Known: true, Black: st.Mode == vpnsvc.ModeBlack, Online: st.Online, Handshake: st.HandshakeS}
		view["tunnelUp"] = st.Present
	}
	scene := vpnSceneOf(f)
	view["scene"] = scene
	view["profileGrid"] = vpnProfileGrid(rows, link, settings.Mode == vpnsvc.ModeBlack, "", "tok")
	slug := settings.ActiveSlug
	if slug == "" && len(rows) > 0 {
		slug = rows[0].Slug
	}
	view["setup"] = vpnSetup(vpnSetupFacts{RolesReady: true, HasProfiles: len(rows) > 0,
		Enabled: settings.Mode == vpnsvc.ModeBlack && settings.ActiveSlug != "", Known: link.Known, Online: link.Online,
		Slug: slug, Settings: settings}, "tok")
	return view
}

func vpnTestRows() []profileView {
	return []profileView{
		{Slug: "fra", Name: "frankfurt-2", Endpoint: "203.0.113.5:51820", Addresses: "10.64.0.2", Active: true, FullTunnel: true,
			Protocol: "WireGuard", Transport: "UDP", VoiceFit: true, Mark: protoMark("wireguard")},
		{Slug: "ams", Name: "amsterdam-1", Endpoint: "ams.example:443", Addresses: "10.8.0.6", FullTunnel: true,
			Protocol: "OpenVPN", Transport: "TCP", Mark: protoMark("openvpn")},
	}
}

func TestVPNPageScenes(t *testing.T) {
	black := vpnsvc.Settings{ActiveSlug: "fra", Mode: vpnsvc.ModeBlack, OnFailure: vpnsvc.FailStrict, DNSChoice: vpnsvc.DNSOurs}
	white := black
	white.Mode = vpnsvc.ModeWhite
	leaky := black
	leaky.OnFailure = vpnsvc.FailDirect
	cases := []struct {
		name     string
		settings vpnsvc.Settings
		rows     []profileView
		st       *vpnsvc.Status
		want     []string
		absent   []string
	}{
		{"поднят", black, vpnTestRows(), &vpnsvc.Status{Mode: vpnsvc.ModeBlack, Present: true, Online: true, HandshakeS: 12, DataPlane: vpndriver.Yes},
			[]string{"Канал поднят: провайдер не видит", "tp-pipe tp-pipe-ok", "только факт подключения", "pc-card pc-current",
				"Канал поднят · обмен с сервером 12 с назад", `action="/vpn/check"`, "data-direct-open"},
			[]string{"Включить VPN для всего офиса", "Весь офис через защищённый канал"}},
		{"обрыв, интернет закрыт", black, vpnTestRows(), &vpnsvc.Status{Mode: vpnsvc.ModeBlack, Present: true},
			[]string{"Канал не отвечает, офис закрыт от интернета", "tp-pipe tp-pipe-broken", "интернет офиса закрыт", `href="#vpn-modes"`}, nil},
		{"обрыв, напрямую", leaky, vpnTestRows(), &vpnsvc.Status{Mode: vpnsvc.ModeBlack, Present: true, Degraded: true},
			[]string{"Канал не отвечает, офис выходит напрямую", "tp-pipe tp-pipe-open", "при обрыве — напрямую"}, nil},
		{"напрямую", white, vpnTestRows(), &vpnsvc.Status{Mode: vpnsvc.ModeWhite},
			[]string{"Офис выходит в интернет напрямую", "адреса всех сайтов", "Включить VPN для всего офиса", `id="vpn-setup"`, `aria-current="step"`,
				`name="mode" value="black"`, `name="on_failure" value="strict"`, `name="profile" value="fra"`},
			[]string{"pc-current"}},
		{"файл загружен", vpnsvc.Settings{Mode: vpnsvc.ModeWhite, OnFailure: vpnsvc.FailStrict}, freshRows(), &vpnsvc.Status{Mode: vpnsvc.ModeWhite},
			[]string{"Файл загружен, осталось включить VPN", "подключение готово", "tp-mark-ok", "Включить VPN для всего офиса"},
			[]string{"Офис выходит в интернет напрямую"}},
		{"нет подключений", vpnsvc.Settings{Mode: vpnsvc.ModeWhite, OnFailure: vpnsvc.FailStrict}, nil, nil,
			[]string{"Офис пока без защиты", "tp-node tp-wait", "tp-mark-add", "pc-empty", "Загрузите файл подключения", `aria-current="step"`},
			[]string{"pc-grid", "data-switch-warn", `name="mode" value="black" checked`}},
		{"служба молчит", black, vpnTestRows(), nil,
			[]string{"Состояние канала неизвестно", "tp-pipe tp-pipe-unknown", "служба молчит"}, nil},
	}
	for _, c := range cases {
		html := renderVPN(t, vpnTestView(c.settings, c.rows, c.st))
		common := []string{`id="vpn-apply"`, `action="/vpn/apply"`, `action="/vpn/import"`, `enctype="multipart/form-data"`,
			`name="config"`, `name="name"`, `form="vpn-mtu"`, `form="vpn-timesync"`, `name="mtu" form="vpn-apply"`,
			`name="mode" value="black"`, `name="on_failure" value="strict"`, "Наблюдение пути", "data-upload"}
		if c.rows != nil {
			common = append(common, `name="profile" value="fra"`, `form="vpn-apply"`, `name="dns_choice"`)
		}
		for _, w := range append(common, c.want...) {
			if !strings.Contains(html, w) {
				t.Errorf("%s: на странице нет %q", c.name, w)
			}
		}
		if c.rows != nil && !profileInApply.MatchString(html) {
			t.Errorf("%s: радиокнопка подключения не принадлежит форме применения", c.name)
		}
		for _, w := range c.absent {
			if strings.Contains(html, w) {
				t.Errorf("%s: на странице лишнее %q", c.name, w)
			}
		}
	}
}

func TestVPNDeleteFollowsServiceRule(t *testing.T) {
	g := vpnProfileGrid(vpnTestRows(), vpnLink{Known: true, Black: true, Online: true}, true, "", "tok")
	if g.Cards[0].Delete != nil || g.Cards[0].DeleteNote == "" {
		t.Fatalf("выбранное при режиме через канал: удаление %+v, объяснение %q", g.Cards[0].Delete, g.Cards[0].DeleteNote)
	}
	w := vpnProfileGrid(vpnTestRows(), vpnLink{Known: true}, false, "", "tok")
	if w.Cards[0].Delete == nil || w.Cards[0].Delete.Hidden["profile"] != "fra" || w.Cards[0].DeleteNote != "" {
		t.Fatalf("выбранное при прямом доступе удаляется: %+v", w.Cards[0])
	}
	d := g.Cards[1].Delete
	if d == nil || d.Action != "/vpn/remove" || d.Hidden["profile"] != "ams" || d.Question == "" {
		t.Fatalf("удаление второго подключения: %+v", d)
	}
	if g.Cards[1].Tags[1].Text != "TCP: для разговоров не годится" {
		t.Fatalf("метка TCP: %+v", g.Cards[1].Tags)
	}
}

func TestVPNEnableKeepsSettings(t *testing.T) {
	f := vpnEnableForm("tok", vpnsvc.Settings{ActiveSlug: "fra", Mode: vpnsvc.ModeWhite, OnFailure: vpnsvc.FailDirect, MTU: 1380, DNSChoice: vpnsvc.DNSConfig}, "fra")
	want := map[string]string{"profile": "fra", "mode": vpnsvc.ModeBlack, "on_failure": vpnsvc.FailDirect, "dns_choice": vpnsvc.DNSConfig, "mtu": "1380"}
	for k, v := range want {
		if f.Hidden[k] != v {
			t.Fatalf("%s = %q, ждали %q", k, f.Hidden[k], v)
		}
	}
}

func vpnTestReport() *vpncheck.Report {
	good := vpncheck.Stats{Sent: 500, Received: 500, AvgMs: 24, JitterMs: 3}
	return &vpncheck.Report{Mode: "quick",
		DirectLeg: vpncheck.Probe{Kind: vpncheck.KindEcho, Stats: vpncheck.Stats{Sent: 500, Received: 500, AvgMs: 19, JitterMs: 2}},
		TunnelLeg: vpncheck.Probe{Kind: vpncheck.KindEcho, Stats: good},
		Data:      vpncheck.Probe{Kind: vpncheck.KindVoice, Stats: vpncheck.Stats{Sent: 1500, Received: 1500, AvgMs: 24, JitterMs: 3}},
		Speed:     &vpncheck.Speed{TunnelDownKbit: 87000, BaselineDownKbit: 94000}}
}

func TestVPNCheckSummary(t *testing.T) {
	grade, g := checkSummary(vpnTestReport())
	if len(g.Metrics) != 4 {
		t.Fatalf("плиток %d, ждали четыре: %+v", len(g.Metrics), g.Metrics)
	}
	if g.Metrics[0].Value != "24" || g.Metrics[0].Note != "напрямую до сервера 19 мс" {
		t.Fatalf("задержка: %+v", g.Metrics[0])
	}
	if g.Metrics[3].Value != "87" || g.Metrics[3].Note != "без канала 94 Мбит/с" {
		t.Fatalf("скорость: %+v", g.Metrics[3])
	}
	if grade.Text == "" || grade.Judged.Level() != ui.OK {
		t.Fatalf("оценка разговора: %+v", grade)
	}
	if _, empty := checkSummary(&vpncheck.Report{}); len(empty.Metrics) != 0 {
		t.Fatalf("без выборки плитки не показываются: %+v", empty.Metrics)
	}
}

func TestVPNMonogram(t *testing.T) {
	for in, want := range map[string]string{"WireGuard": "WG", "OpenVPN": "OV", "Shadow Link Pro": "SL", "ikev": "IK"} {
		if got := monogram(in); got != want {
			t.Fatalf("%s: %q, ждали %q", in, got, want)
		}
	}
	if m := protoMark("wireguard"); m.Mono != "WG" || m.Tone != 1 {
		t.Fatalf("значок WireGuard: %+v", m)
	}
}

func TestVPNTunnelNeedsProfile(t *testing.T) {
	none := vpnModeCards(true, false)
	if !none.Options[0].Disabled || none.Options[0].Checked || !none.Options[1].Checked {
		t.Fatalf("без подключений: %+v", none.Options)
	}
	if none.Options[0].Label != "Весь офис через VPN" {
		t.Fatalf("название режима: %q", none.Options[0].Label)
	}
	if some := vpnModeCards(true, true); some.Options[0].Disabled || !some.Options[0].Checked {
		t.Fatalf("с подключениями: %+v", some.Options)
	}
}

func TestVPNPreselectAndFresh(t *testing.T) {
	rows := vpnTestRows()
	rows[0].Active = false
	g := vpnProfileGrid(rows, vpnLink{}, false, "ams", "tok")
	if !g.Cards[0].Checked || g.Cards[1].Checked || g.Cards[0].PickLabel != "Выбрано" {
		t.Fatalf("предвыбор: %+v / %+v", g.Cards[0], g.Cards[1])
	}
	if !g.Cards[1].Fresh || g.Cards[1].Tags[0].Text != "только что загружено" || g.Cards[0].Fresh {
		t.Fatalf("свежее подключение: %+v", g.Cards[1])
	}
}

func TestVPNSetupSteps(t *testing.T) {
	base := vpnSetupFacts{RolesReady: true, HasProfiles: true, Slug: "fra", Settings: vpnsvc.Settings{ActiveSlug: "fra"}}
	c := vpnSetup(base, "tok")
	if c == nil || c.Steps[2].State != "current" || c.Steps[2].Action == nil || c.Steps[2].Action.Hidden["mode"] != vpnsvc.ModeBlack {
		t.Fatalf("после загрузки текущий шаг — включить канал: %+v", c)
	}
	if c.Steps[0].State != "done" || c.Steps[3].State != "todo" || c.DoneCount() != 2 {
		t.Fatalf("состояния шагов: %+v", c.Steps)
	}
	none := vpnSetup(vpnSetupFacts{}, "tok")
	if none.Steps[0].State != "current" || none.Steps[0].Link == nil || none.Steps[2].Action != nil {
		t.Fatalf("пустой шлюз: %+v", none.Steps)
	}
	all := base
	all.Enabled, all.Known, all.Online, all.Checked = true, true, true, true
	if vpnSetup(all, "tok") != nil {
		t.Fatal("всё сделано, а помощь видна")
	}
}

func TestVPNReconnectView(t *testing.T) {
	f, wait := vpnReconnectView(&vpnsvc.Status{Mode: vpnsvc.ModeBlack}, 0, "tok")
	if f == nil || f.Action != "/vpn/reconnect" || wait != "" {
		t.Fatalf("обрыв: %+v %q", f, wait)
	}
	if f, wait := vpnReconnectView(&vpnsvc.Status{Mode: vpnsvc.ModeBlack}, 40*time.Second, "tok"); f != nil || wait != "40 с" {
		t.Fatalf("после нажатия: %+v %q", f, wait)
	}
	for _, st := range []*vpnsvc.Status{nil, {Mode: vpnsvc.ModeBlack, Online: true}, {Mode: vpnsvc.ModeWhite}} {
		if f, _ := vpnReconnectView(st, 0, "tok"); f != nil {
			t.Fatalf("кнопка не к месту: %+v", st)
		}
	}
}

func freshRows() []profileView {
	r := vpnTestRows()[:1]
	r[0].Active = false
	return r
}
