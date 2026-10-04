package priority

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/admission"
)

var routeRe = regexp.MustCompile(`Route\(\)\.(Get|Post)\("([^"]+)"`)

func TestEveryRouteHasExplicitClass(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "routes", "web.go"))
	if err != nil {
		t.Fatalf("маршруты не прочитаны: %v", err)
	}
	matches := routeRe.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 40 {
		t.Fatalf("маршрутов найдено %d — разбор смотрит не туда", len(matches))
	}
	for _, m := range matches {
		method, path := map[string]string{"Get": "GET", "Post": "POST"}[m[1]], m[2]
		if !hasExactRule(method, path) {
			cls, _ := admission.Classify(Rules, method, path)
			t.Errorf("маршрут %s %s без явного класса (сейчас достался бы «%v» по общему правилу)", method, path, cls)
		}
	}
}

func hasExactRule(method, path string) bool {
	for _, r := range Rules {
		if r.Prefix == path && (r.Method == "" || r.Method == method) {
			return true
		}
	}

	for _, r := range Rules {
		if r.Method == method && r.Prefix != "/" && len(path) > len(r.Prefix) && path[:len(r.Prefix)+1] == r.Prefix+"/" {
			return true
		}
	}
	return false
}

func TestUnknownRouteIsCaught(t *testing.T) {
	if hasExactRule("GET", "/nowhere") || hasExactRule("POST", "/nowhere/deep") {
		t.Fatal("неизвестный маршрут сошёл за записанный")
	}
}

func TestClassAnchors(t *testing.T) {
	cases := []struct {
		method, path string
		want         admission.Class
	}{
		{"POST", "/login", admission.Critical},
		{"POST", "/vpn/apply", admission.Critical},
		{"POST", "/security/logs-trim", admission.Critical},
		{"GET", "/security", admission.Ordinary},
		{"GET", "/public/css/app.css", admission.Ordinary},
		{"GET", "/whoami", admission.Ordinary},
		{"GET", "/qos/speedtest/status", admission.Sheddable},
		{"POST", "/lantest/probe", admission.Sheddable},
		{"GET", "/search", admission.Sheddable},
	}
	for _, c := range cases {
		if got, _ := admission.Classify(Rules, c.method, c.path); got != c.want {
			t.Errorf("%s %s: %v, ожидалось %v", c.method, c.path, got, c.want)
		}
	}
}
