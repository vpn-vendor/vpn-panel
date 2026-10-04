package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("jwt", map[string]any{

		"secret": config.Env("JWT_SECRET", ""),

		"ttl": config.Env("JWT_TTL", 60),

		"refresh_ttl": config.Env("JWT_REFRESH_TTL", 20160),
	})
}
