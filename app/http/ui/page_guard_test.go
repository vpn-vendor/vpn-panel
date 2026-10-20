package ui_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readTree(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{"..", "..", ".."}, parts...)...)
	b, err := os.ReadFile(p) //nolint:gosec
	if err != nil {
		t.Fatalf("%s не читается: %v", p, err)
	}
	return string(b)
}

func TestPageGuardBudgetsAreDerived(t *testing.T) {
	js := readTree(t, "public", "js", "islands.js")
	for _, want := range []string{

		"window.setTimeout(flushResize, RESIZE_QUIET_MS)",
		"REDRAWS_PER_ISLAND * islands.length * elapsed",
		"Math.min(window.devicePixelRatio || 1, DPR_CAP)",
		"* BYTES_PER_PIXEL",
		`supportedEntryTypes`,
		`streak[why] >= STREAK_WINDOWS`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("в ядре островов нет выражения %q — форма бюджета изменилась", want)
		}
	}
	power := regexp.MustCompile(`(?i)\b[0-9]+\s*\*\s*1024\b|\b[0-9]+\s*(мб|mb|мс на|ms per)`)
	if m := power.FindString(js); m != "" {
		t.Errorf("в ядре островов число мощности константой: %q (закон)", m)
	}
}

func TestPageGuardDegradesByCapability(t *testing.T) {
	js := readTree(t, "public", "js", "islands.js")
	for _, want := range []string{"window.MutationObserver", "window.ResizeObserver", "window.WeakSet", "window.requestAnimationFrame", "!!fuseNote()"} {
		if !strings.Contains(js, want) {
			t.Errorf("проверка возможностей потеряла %q", want)
		}
	}
}

func TestFuseNoteIsServedHiddenAndHuman(t *testing.T) {
	tpl := readTree(t, "resources", "views", "partials.tmpl")
	block := regexp.MustCompile(`(?s)\{\{ define "island-fuse" \}\}(.*?)\{\{ end \}\}`).FindStringSubmatch(tpl)
	if block == nil {
		t.Fatal("в оболочке нет блока island-fuse")
	}
	body := block[1]
	for _, want := range []string{`id="island-fuse"`, `role="alert"`, " hidden", "Обновите страницу", "данные на сервере целы"} {
		if !strings.Contains(body, want) {
			t.Errorf("плашка предохранителя потеряла %q", want)
		}
	}
	text := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, " ")
	if m := regexp.MustCompile(`[A-Za-z]{3,}`).FindString(text); m != "" {
		t.Errorf("в тексте плашки сырое техническое слово %q", m)
	}
	top := regexp.MustCompile(`(?s)\{\{ define "app-top" \}\}(.*?)\n\{\{ end \}\}`).FindStringSubmatch(tpl)
	if top == nil || !strings.Contains(top[1], `{{ template "island-fuse" . }}`) {
		t.Error("оболочка за входом не зовёт плашку предохранителя — острова на её страницах не запустятся")
	}
}

func TestCoreObeysItsOwnContract(t *testing.T) {
	for _, name := range []string{"app.js", "islands.js"} {
		js := readTree(t, "public", "js", name)
		for _, banned := range []string{"innerHTML", "insertAdjacentHTML", `createElement("canvas")`, "OffscreenCanvas"} {
			if strings.Contains(js, banned) {
				t.Errorf("в сценарии %s есть %q", name, banned)
			}
		}
	}
	tpl := readTree(t, "resources", "views", "partials.tmpl")
	core := strings.Index(tpl, `<script src="{{ .static }}/js/islands.js" defer></script>`)
	search := strings.Index(tpl, `<script src="{{ .static }}/js/search.js" defer></script>`)
	if core < 0 || search < 0 || core > search {
		t.Error("ядро островов обязано подключаться с defer и раньше остальных отложенных сценариев оболочки")
	}
}

func TestNavigationAsksTheStyleNotTheScreen(t *testing.T) {
	js := readTree(t, "public", "js", "app.js")
	for _, want := range []string{
		`getPropertyValue("--nav-mode")`,
		`root.classList.add("js-nav")`,
		`aria-expanded`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("сценарий оболочки потерял %q", want)
		}
	}
	if m := regexp.MustCompile(`\b(min|max)-width\b|\b\d{3,4}px\b|\b\d{2,3}em\b`).FindString(js); m != "" {
		t.Errorf("в сценарии оболочки ширина экрана %q — её место в стилях", m)
	}

	for _, want := range []string{`"Escape"`, "lastFocus"} {
		if !strings.Contains(js, want) {
			t.Errorf("выдвижное меню потеряло %q — с клавиатуры из него не выйти", want)
		}
	}
}

func TestShellAnimatesOnlyCheapThings(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	for _, line := range strings.Split(css, "\n") {
		i := strings.Index(line, "transition:")
		if i < 0 || strings.HasPrefix(strings.TrimSpace(line), "/*") {
			continue
		}
		for _, banned := range []string{"width", "height", "inset", "top", "left", "margin", "padding", "all"} {
			if regexp.MustCompile(`transition:[^;]*\b` + banned + `\b`).MatchString(line) {
				t.Errorf("анимация раскладки (%s): %s", banned, strings.TrimSpace(line))
			}
		}
	}
}

func TestDrawerKeepsFocusInside(t *testing.T) {
	js := readTree(t, "public", "js", "app.js")
	for _, want := range []string{
		`sidebar.contains(document.activeElement)`,
		"e.shiftKey ? last : first",
		"e.preventDefault()",
		`lastFocus.focus()`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("ловушка фокуса потеряла %q", want)
		}
	}
}

func mediaBlocks(t *testing.T, css, header string) []string {
	t.Helper()
	var out []string
	for i := 0; ; {
		k := strings.Index(css[i:], header)
		if k < 0 {
			break
		}
		depth, start := 0, i+k+len(header)
		for j := start; j < len(css); j++ {
			if css[j] == '{' {
				depth++
			} else if css[j] == '}' {
				if depth == 0 {
					out = append(out, css[start:j])
					i = j
					break
				}
				depth--
			}
		}
		if i < start {
			t.Fatalf("блок %q не закрыт", header)
		}
	}
	if len(out) == 0 {
		t.Fatalf("в стилях нет блока %q", header)
	}
	return out
}

func TestMenuRailOpensOverTheSheet(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	docked := mediaBlocks(t, css, "@media (min-width: 48em) {")
	outside := css
	var all string
	for _, b := range docked {
		all += b
		outside = strings.Replace(outside, b, "", 1)
	}
	for _, want := range []string{
		"width: var(--sidebar-rail-w); flex: 0 0 var(--sidebar-rail-w);",
		".sidebar:hover :is(.nav-panel, .nav-track), .sidebar:focus-within :is(.nav-panel, .nav-track)",
		":root.nav-pinned .sidebar { width: var(--sidebar-w);",
		"transform: translateX(calc(var(--nav-shift) * -1));",
		"transform: translateX(var(--nav-shift));",
		".sidebar:hover :is(.nav-panel, .nav-track) { transition-delay:",
		"--nav-slide: var(--motion-3) var(--ease-slide);",
		"transition: transform var(--nav-slide);",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("в режиме потока нет %q", want)
		}
	}

	if strings.Contains(all, ".nav-panel { box-shadow") {
		t.Error("у раскрытой панели меню снова тень: сдвиг пойдёт рывками на программной отрисовке")
	}

	touch := mediaBlocks(t, css, "@media (min-width: 48em) and (hover: none) {")
	if !strings.Contains(touch[0], "width: var(--sidebar-w)") ||
		!strings.Contains(touch[0], ":root:not(.nav-pinned) .sidebar:not(:hover):not(:focus-within) :is(.nav-text, .nav-head-title) { opacity: 1; }") {
		t.Error("на экране без наведения меню обязано стоять раскрытым, с видимыми подписями")
	}
	if regexp.MustCompile(`\.sidebar[^{]*\{[^}]*display:\s*none`).MatchString(css) {
		t.Error("меню скрывается целиком: на компьютере оно рельса, в шторке уезжает за край")
	}
	if strings.Contains(outside, "--sidebar-rail-w)") {
		t.Error("рельса применяется вне режима потока: шторка обязана оставаться во всю ширину")
	}
	js := readTree(t, "public", "js", "app.js")
	for _, gone := range []string{"sidebar-collapsed", "sidebar-open", "sidebar-away", "nav-edge", "sidebar-edge",
		"nav-closed", "nav-away", "sidebar-fold", "nav-fold"} {
		if strings.Contains(css, gone) || strings.Contains(js, gone) {
			t.Errorf("прежнее состояние меню %q не убрано — два состояния снова могут встретиться", gone)
		}
	}
	for _, want := range []string{
		`root.classList.toggle("nav-open", opened)`,
		`root.classList.toggle("nav-pinned")`,
		`"vp-nav-pin"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("меню потеряло %q", want)
		}
	}
}

func TestPhoneContentStaysInside(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	for _, want := range []string{
		".item-list .item-card > .seg { grid-column: 1 / -1; }",
		"@container item-list (max-width: 16rem)",
		"display: block; padding: var(--s2) 0 var(--s2) var(--fold-hang); text-indent:",
		".choice-card-body { display: grid; grid-template-columns: minmax(0, 1fr);",
		".card-head-wrap > :not(:first-child) { flex: 0 1 auto; min-width: 0; }",
		".table-wrap { max-width: 100%; overflow-x: auto; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("в стилях нет %q", want)
		}
	}
	for _, f := range []string{"metrics.tmpl", "storage.tmpl"} {
		if !strings.Contains(readTree(t, "resources", "views", "security", f), `<div class="table-wrap">`) {
			t.Errorf("таблица в %s без обёртки прокрутки: на компьютере налезет на соседнюю колонку", f)
		}
	}
}

func TestUnsavedChangesAreNeverSilent(t *testing.T) {
	shell := readTree(t, "resources", "views", "partials.tmpl")
	if !strings.Contains(shell, `{{ template "components/unsaved-bar" }}`) {
		t.Error("в оболочке нет полосы несохранённых изменений")
	}
	if !strings.Contains(readTree(t, "resources", "views", "components", "unsaved-bar.tmpl"), "data-unsaved-bar role=\"status\" aria-live=\"polite\" hidden") {
		t.Error("полоса обязана приходить скрытой: без сценария у форм свои кнопки")
	}
	core := readTree(t, "public", "js", "app.js")
	for _, want := range []string{`querySelectorAll("form[data-unsaved]")`, `"beforeunload"`, `new Event("change", { bubbles: true })`} {
		if !strings.Contains(core, want) {
			t.Errorf("в ядре нет %q", want)
		}
	}
	for _, f := range [][]string{
		{"network.tmpl", `action="/network/apply" id="net-apply" data-unsaved`},
		{"vpn.tmpl", `id="vpn-apply" class="vpn-mode-form" data-unsaved`},
		{"qos.tmpl", `action="/qos/apply" data-island="qos-form" data-unsaved`},
		{"security/retention.tmpl", `action="/security/retention" data-unsaved`},
		{"security/outside.tmpl", `action="/security/apply" data-unsaved`},
	} {
		if !strings.Contains(readTree(t, append([]string{"resources", "views"}, strings.Split(f[0], "/")...)...), f[1]) {
			t.Errorf("форма настроек в %s не помечена data-unsaved", f[0])
		}
	}
}

func TestTrafficPathIsARibbonOnPhone(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	for _, want := range []string{
		"grid-template-columns: auto minmax(var(--s2), 1fr) auto minmax(calc(var(--ctl-sm) + var(--s4)), 1.8fr) auto minmax(var(--s2), 1fr) auto;",
		".tp-tunnel { display: contents; }",
		".tp-isp { grid-column: 1 / -1; grid-row: 2;",
		".tp-name-more, .tp-sub, .tp-tunnel > .tag { display: none; }",
		"@container (min-width: 52rem) {\n  .tp { --tp-tile: calc(var(--ctl-lg) + var(--s4));",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("в стилях схемы нет %q", want)
		}
	}
	if !strings.Contains(readTree(t, "resources", "views", "components", "traffic-path.tmpl"), `Сервер<span class="tp-name-more"> VPN</span>`) {
		t.Error("подпись сервера на ленте должна сокращаться до «Сервер»")
	}
}

func TestChartPanelStaysPutAndClosesOutside(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	if regexp.MustCompile(`(?m)^\.chart-panel\s*\{[^}]*\bposition\s*:`).MatchString(css) {
		t.Error("у .chart-panel задано position: окно перестанет стоять на месте при прокрутке")
	}
	if !strings.Contains(css, "html:has(.chart-panel[open]) { overflow: hidden; scrollbar-gutter: stable; }") {
		t.Error("страница под открытым окном графика должна стоять")
	}
	js := readTree(t, "public", "js", "dashboard.js")
	for _, want := range []string{`h.on(root, "click", function (e) {`, `if (e.target !== root) { return; }`, `root.getBoundingClientRect()`} {
		if !strings.Contains(js, want) {
			t.Errorf("окно графика не закрывается щелчком мимо: нет %q", want)
		}
	}
}
