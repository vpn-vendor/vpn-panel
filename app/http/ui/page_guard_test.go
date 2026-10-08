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
		`getPropertyValue("--calm")`,
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

func TestMenuHasOneStateWithTwoReadings(t *testing.T) {
	css := readTree(t, "public", "css", "app.css")
	docked := mediaBlocks(t, css, "@media (min-width: 48em) {")
	hidden, outside := false, css
	for _, b := range docked {
		if strings.Contains(b, ".nav-closed .sidebar { display: none; }") {
			hidden = true
		}
		outside = strings.Replace(outside, b, "", 1)
	}
	if !hidden {
		t.Error("скрытие меню обязано быть объявлено в режиме потока")
	}
	if regexp.MustCompile(`\.sidebar[^{]*\{[^}]*display:\s*none`).MatchString(outside) {
		t.Error("меню скрывается вне режима потока: в выдвижном режиме это даёт затемнение без меню")
	}
	for _, gone := range []string{"sidebar-collapsed", "sidebar-open", "sidebar-away"} {
		if strings.Contains(css, gone) || strings.Contains(readTree(t, "public", "js", "app.js"), gone) {
			t.Errorf("прежнее состояние меню %q не убрано — два состояния снова могут встретиться", gone)
		}
	}
	js := readTree(t, "public", "js", "app.js")
	for _, want := range []string{
		`root.classList.toggle("nav-open", opened)`,
		`root.classList.toggle("nav-closed", !opened)`,
		"return !drawer();",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("состояние меню потеряло %q", want)
		}
	}
}
