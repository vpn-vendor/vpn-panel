package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("queue", map[string]any{

		"default": "sync",

		"connections": map[string]any{
			"sync": map[string]any{
				"driver": "sync",
			},
			"database": map[string]any{
				"driver":     "database",
				"connection": config.Env("DB_CONNECTION"),
				"queue":      "default",
				"concurrent": 1,
			},
		},

		"failed": map[string]any{
			"database": config.Env("DB_CONNECTION"),
			"table":    "failed_jobs",
		},
	})
}
