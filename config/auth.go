package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("auth", map[string]any{

		"defaults": map[string]any{
			"guard": "user",
		},

		"guards": map[string]any{
			"user": map[string]any{
				"driver":   "jwt",
				"provider": "user",
			},
		},

		"providers": map[string]any{
			"user": map[string]any{
				"driver": "orm",
			},
		},
	})
}
