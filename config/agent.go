package config

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("agent", map[string]any{

		"socket": config.Env("AGENT_SOCKET", "/run/vpn-panel/broker.sock"),
	})
}
