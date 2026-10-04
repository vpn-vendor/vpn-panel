package config

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/services/logsink"
)

func init() {
	config := facades.Config()
	config.Add("logging", map[string]any{

		"default": config.Env("LOG_CHANNEL", "stack"),

		"channels": map[string]any{
			"stack": map[string]any{
				"driver":   "stack",
				"channels": []string{"journal"},
			},
			"journal": map[string]any{
				"driver": "custom",
				"via":    logsink.Driver{Level: fmt.Sprint(config.Env("LOG_LEVEL", "debug"))},
			},
		},
	})
}
