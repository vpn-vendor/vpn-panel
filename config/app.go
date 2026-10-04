package config

import (
	"github.com/goravel/framework/support/carbon"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func Boot() {}

func init() {
	config := facades.Config()
	config.Add("app", map[string]any{

		"name": config.Env("APP_NAME", "VPN Panel"),

		"env": config.Env("APP_ENV", "production"),

		"debug": config.Env("APP_DEBUG", false),

		"timezone": carbon.UTC,

		"locale": "en",

		"fallback_locale": "en",

		"key": config.Env("APP_KEY", ""),
		"maintenance": map[string]any{

			"driver": config.Env("APP_MAINTENANCE_DRIVER", "file"),

			"store": config.Env("APP_MAINTENANCE_STORE", ""),
		},
	})
}
