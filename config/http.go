package config

import (
	"github.com/goravel/framework/contracts/route"
	ginfacades "github.com/goravel/gin/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("http", map[string]any{
		"default": "gin",

		"drivers": map[string]any{
			"gin": map[string]any{
				"body_limit":   4096,
				"header_limit": 4096,
				"route": func() (route.Route, error) {
					return ginfacades.Route("gin"), nil
				},
			},
		},

		"url": config.Env("APP_URL", "https://vpn.lan"),

		"host": "",

		"port": "",

		"request_timeout": 120,

		"redirect_port": config.Env("APP_PORT", "80"),

		"external_tls_port": config.Env("APP_EXTERNAL_TLS_PORT", ""),

		"tls": map[string]any{

			"host": "",

			"port": config.Env("APP_TLS_PORT", "443"),

			"ssl": map[string]any{
				"cert": config.Env("TLS_CERT", "/var/lib/vpn-panel/tls/cert.pem"),
				"key":  config.Env("TLS_KEY", "/var/lib/vpn-panel/tls/key.pem"),
			},
		},

		"default_client": config.Env("HTTP_CLIENT_DEFAULT", "default"),

		"clients": map[string]any{
			"default": map[string]any{

				"base_url": config.Env("HTTP_CLIENT_BASE_URL", ""),

				"timeout": config.Env("HTTP_CLIENT_TIMEOUT", "30s"),

				"max_idle_conns": config.Env("HTTP_CLIENT_MAX_IDLE_CONNS", 100),

				"max_idle_conns_per_host": config.Env("HTTP_CLIENT_MAX_IDLE_CONNS_PER_HOST", 2),

				"max_conns_per_host": config.Env("HTTP_CLIENT_MAX_CONN_PER_HOST", 0),

				"idle_conn_timeout": config.Env("HTTP_CLIENT_IDLE_CONN_TIMEOUT", "90s"),
			},
		},
	})
}
