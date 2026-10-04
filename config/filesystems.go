package config

import (
	"github.com/goravel/framework/support/path"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("filesystems", map[string]any{

		"default": "local",

		"disks": map[string]any{
			"local": map[string]any{
				"driver": "local",
				"root":   path.Storage("app"),
			},
			"public": map[string]any{
				"driver": "local",
				"root":   path.Storage("app/public"),
				"url":    config.Env("APP_URL", "").(string) + "/storage",
			},
		},
	})
}
