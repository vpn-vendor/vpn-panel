package middleware

import (
	"strings"
	"testing"
)

func TestCacheControlByPath(t *testing.T) {
	fp := "/static/0123456789abcdef"
	cases := map[string]string{
		fp + "/css/app.css":      "public, max-age=31536000, immutable",
		fp + "/js/islands.js":    "public, max-age=31536000, immutable",
		"/public/css/app.css":    "no-cache",
		"/":                      "no-store",
		"/devices":               "no-store",
		"/metrics/series":        "no-store",
		"/public":                "no-store",
		"/publicity/css/app.css": "no-store",
	}
	for path, want := range cases {
		if got := CacheControlFor(path, fp); got != want {
			t.Errorf("%s: %q, ожидалось %q", path, got, want)
		}
	}
	if !strings.Contains(CacheControlFor(fp+"/x", fp), "immutable") {
		t.Error("статика с отпечатком не помечена неизменяемой")
	}
}
