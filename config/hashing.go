package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("hashing", map[string]any{

		"driver": "bcrypt",

		"bcrypt": map[string]any{
			"rounds": 12,
		},

		"argon2id": map[string]any{
			"memory":  65536,
			"time":    4,
			"threads": 1,
		},
	})
}
