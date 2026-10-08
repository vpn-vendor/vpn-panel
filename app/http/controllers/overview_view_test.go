package controllers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
	"github.com/vpn-vendor/vpn-panel-core/internal/rtnl"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

func renderOverview(t *testing.T, f overviewFacts) string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "resources", "views")
	atoms, err := filepath.Glob(filepath.Join(root, "components", "*.tmpl"))
	if err != nil || len(atoms) == 0 {
		t.Fatalf("атомы не найдены: %v", err)
	}
	files := append([]string{filepath.Join(root, "partials.tmpl"), filepath.Join(root, "overview.tmpl")}, atoms...)
	tpl, err := template.ParseFiles(files...)
	if err != nil {
		t.Fatalf("шаблоны обзора не разбираются: %v", err)
	}
	data := overviewView(f)
	data["title"], data["subtitle"], data["active"], data["version"], data["searchQuery"], data["static"] = "Обзор", "", "home", "", "", "/public"
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "overview.tmpl", data); err != nil {
		t.Fatalf("обзор не отрисовался: %v", err)
	}
	return buf.String()
}

func sampleFacts(protected bool) overviewFacts {
	f := overviewFacts{
		Protected: protected, Online: 14, Version: "0.3.0",
		Protect: metrics.Protect{OK: true, CPUBusy: 22, PressureCPU: 1},
		Norm:    metrics.VoiceNorm{TargetMs: 5, IntervalMs: 100}, HasNorm: true,
		Latest:  func(row string) (float64, bool) { return 2.5, true },
		Updates: &updates.Status{Enabled: true},
		Paths: []pathmon.Snapshot{
			{Kind: pathmon.Direct, State: pathprobe.Up, RTT: 4 * time.Millisecond, LossKnown: true},
			{Kind: pathmon.Tunnel, State: pathprobe.Up, RTT: 31 * time.Millisecond, LossKnown: true, Since: time.Now().Add(-3 * time.Hour)},
		},
	}
	if protected {
		f.Channel = &vpn.Status{Online: true, Endpoint: "vpn.example", MTU: 1440, OutboundGuard: true, BlockedOutbound: 7}
	}
	return f
}

func TestOverviewAsksOnlyDeclaredRows(t *testing.T) {
	declared := map[string]bool{}
	roles := func() metrics.Roles { return metrics.Roles{} }
	links := metrics.NewLinkSource(roles, func() ([]rtnl.Link, error) { return nil, nil })
	qos := metrics.NewQoSSource(roles, func() ([]rtnl.Qdisc, error) { return nil, nil }, func() ([]rtnl.Link, error) { return nil, nil })
	for _, s := range metrics.Sources(links, qos) {
		for _, r := range s.Rows {
			declared[r] = true
		}
	}
	for _, r := range pathmon.Rows() {
		declared[r] = true
	}
	attr := regexp.MustCompile(`data-rows="([^"]*)"`)
	for _, protected := range []bool{false, true} {
		found := 0
		for _, m := range attr.FindAllStringSubmatch(renderOverview(t, sampleFacts(protected)), -1) {
			for _, row := range strings.Split(m[1], ",") {
				found++
				if !declared[row] {
					t.Errorf("защищённый режим=%v: страница просит ряд %q, которого нет в реестре сборщика", protected, row)
				}
			}
		}
		if found < 8 {
			t.Fatalf("защищённый режим=%v: найдено подозрительно мало рядов (%d) — сломан сам тест", protected, found)
		}
	}
}

func TestOverviewIsMeaningfulWithoutScript(t *testing.T) {
	direct := renderOverview(t, sampleFacts(false))
	for _, want := range []string{"Интернет работает", "Звонки в норме", "Сервер не перегружен", "2,5 мс",
		"прямой доступ", "Устройств в сети сейчас", "14", "v0.3.0", `data-rows="net.wan.rx,net.wan.tx"`, `data-norm="5"`,
		`data-warn="70"`, `data-bad="85"`, `src="/public/js/dashboard.js" defer`, `class="link-card-go"`} {
		if !strings.Contains(direct, want) {
			t.Errorf("прямой доступ: на странице нет %q", want)
		}
	}
	protected := renderOverview(t, sampleFacts(true))
	for _, want := range []string{"офис выходит через VPN", `data-rows="net.tunnel.rx,net.tunnel.tx"`, `data-rows="qos.tunnel.voice.delay"`,
		`data-rows="path.tunnel.loss,path.tunnel.rtt"`, `data-alive="path.tunnel.rtt"`, "VPN не отвечает", "поднят", "без обрыва 3 ч", "vpn.example", "1440", "31 мс", "заблокировано", ">7<"} {
		if !strings.Contains(protected, want) {
			t.Errorf("защищённый режим: на странице нет %q", want)
		}
	}

	if n := strings.Count(direct, "<canvas"); n != 8 {
		t.Errorf("полотен на странице %d, ждали 8 — семь карточек и панель", n)
	}
	if n := strings.Count(direct, "<dialog"); n != 1 {
		t.Errorf("развёрнутых панелей %d, должна быть одна", n)
	}
	for _, inline := range []string{"style=\"", "onclick="} {
		if strings.Contains(direct+protected, inline) {
			t.Errorf("на странице инлайн %q", inline)
		}
	}

	text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(direct+protected, " ")
	if m := regexp.MustCompile(`(?i)\b(rtt|jitter|rx|tx|latency|loss)\b`).FindString(text); m != "" {
		t.Errorf("в тексте страницы сырой термин %q", m)
	}
}

func TestOverviewNeverClaimsWithoutData(t *testing.T) {
	f := overviewFacts{Protected: true, Online: -1, CollectOff: true,
		Latest: func(string) (float64, bool) { return 1, true },
		Norm:   metrics.VoiceNorm{TargetMs: 5, IntervalMs: 100}, HasNorm: true,
		Protect: metrics.Protect{OK: true, CPUBusy: 5},
		Paths:   []pathmon.Snapshot{{Kind: pathmon.Tunnel, State: pathprobe.Up, LossKnown: true}}}
	out := renderOverview(t, f)
	for _, banned := range []string{"status-ok", "Звонки в норме<", "Сервер не перегружен<"} {
		if strings.Contains(out, banned) {
			t.Errorf("сбор остановлен, а страница утверждает %q", banned)
		}
	}
	for _, want := range []string{"получить не удалось", "Звонки: нет данных", "status-unknown"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет честного текста %q", want)
		}
	}
	noQueue := sampleFacts(false)
	noQueue.HasNorm = false
	if out := renderOverview(t, noQueue); !strings.Contains(out, "Очередь для звонков не включена") || strings.Contains(out, "data-norm=") {
		t.Error("без очереди страница обязана сказать об этом и не рисовать зону нормы")
	}
}

func TestFormatUnitMatchesDashboardScript(t *testing.T) {
	cases := []struct {
		v    float64
		unit string
		want string
	}{{5.9e6, "bits", "47 Мбит/с"}, {125000, "bits", "1,0 Мбит/с"}, {50, "bits", "400 бит/с"}, {2.46, "ms", "2,5 мс"},
		{31, "ms", "31 мс"}, {41.6, "percent", "42 %"}, {0.25, "rate", "0,3 /с"}}
	for _, c := range cases {
		if got := formatUnit(c.v, c.unit); got != c.want {
			t.Errorf("formatUnit(%v, %q) = %q, ждали %q", c.v, c.unit, got, c.want)
		}
	}
}

func TestServerFactsAnswerAdminQuestions(t *testing.T) {
	f := sampleFacts(true)
	f.Machine = sysinfo.Machine{
		CPU:      sysinfo.CPU{Model: "Intel(R) Celeron(R) CPU J1900", Cores: 4, Threads: 4},
		MemBytes: 4 << 30, OSName: "Ubuntu 26.04.1 LTS", Kernel: "7.0.0-31-generic",
		Disks: []sysinfo.Disk{{Name: "sda", Model: "Samsung SSD 870", Kind: "SSD", Bytes: 240 << 30}},
	}
	f.Boot, f.BootOK = sysinfo.Boot{Since: time.Now().Add(-50 * time.Hour), For: 50 * time.Hour}, true
	f.Ports = []sysinfo.Port{
		{Name: "ens3", Driver: "e1000e", SpeedMbit: 1000, Duplex: "full", SpeedKnown: true},
		{Name: "ens4", Driver: "r8169", SpeedMbit: 100, Duplex: "full", SpeedKnown: true},
		{Name: "ens5", Driver: "virtio_net"},
	}
	out := renderOverview(t, f)

	for _, want := range []string{"Intel(R) Celeron(R) CPU J1900", "4 ядра, 4 потока",
		"Ускорение шифрования", "Samsung SSD 870", "SSD", "Ubuntu 26.04.1 LTS", "Ядро 7.0.0-31-generic",
		"Работает без перезагрузки", "2 сут"} {
		if !strings.Contains(out, want) {
			t.Errorf("паспорт сервера потерял %q", want)
		}
	}

	if !strings.Contains(out, "Узкое место") || !strings.Contains(out, "100 Мбит/с") {
		t.Error("стомегабитный порт обязан быть назван узким местом")
	}
	if !strings.Contains(out, "неизвестно") {
		t.Error("порт, не сообщающий скорость, обязан говорить «неизвестно», а не «0 Мбит/с»")
	}
	if regexp.MustCompile(`class="fact-value">\s*0 Мбит/с`).MatchString(out) {
		t.Error("нуль вместо неизвестного читается как факт")
	}

	if !strings.Contains(out, "упрётся в процессор") {
		t.Error("отсутствие ускорения шифрования обязано объясняться последствием")
	}

	rows := regexp.MustCompile(`class="fact( fact-\w+)?"`).FindAllString(out, -1)
	notes := strings.Count(out, "fact-note")
	if len(rows) < 8 || notes < len(rows)-1 {
		t.Errorf("строк %d, пояснений %d — число без объяснения бесполезно", len(rows), notes)
	}
}

func TestAccountMenuHasSignOut(t *testing.T) {
	html := renderOverview(t, sampleFacts(true))
	if !strings.Contains(html, `action="/logout"`) || !strings.Contains(html, `method="post"`) {
		t.Fatal("в меню аккаунта нет формы выхода")
	}
	if strings.Contains(html, "Выйти<span class=\"menu-soon\">") {
		t.Fatal("выход остался заглушкой «в разработке»")
	}
}
