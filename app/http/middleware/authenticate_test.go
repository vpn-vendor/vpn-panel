package middleware

import (
	"strings"
	"testing"
)

func TestMonitoringNeedsLogin(t *testing.T) {
	for _, path := range []string{"/", "/metrics/series", "/metrics", "/overview/feed"} {
		for _, p := range openPrefixes {
			if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
				t.Errorf("%s открыт без входа строкой %q", path, p)
			}
		}
	}
}
