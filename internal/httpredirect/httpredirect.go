package httpredirect

import (
	"net"
	"net/http"
)

func Handler(externalTLSPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := "https://" + host
		if externalTLSPort != "" && externalTLSPort != "443" {
			target += ":" + externalTLSPort
		}
		target += r.URL.RequestURI()

		http.Redirect(w, r, target, http.StatusMovedPermanently) //nolint:gosec
	})
}
