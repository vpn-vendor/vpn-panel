package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("cache", map[string]any{

		"default": "memory",

		"stores": map[string]any{
			"memory": map[string]any{
				"driver": "memory",
			},
		},

		"prefix": config.GetString("APP_NAME", "vpn-panel") + "_cache",
	})
}
