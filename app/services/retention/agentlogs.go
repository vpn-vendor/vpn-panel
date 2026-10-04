package retention

import (
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

type TrimResult struct {
	Freed uint64            `json:"freed"`
	Files map[string]uint64 `json:"files"`
}

func TrimSyslog(files []string) (*TrimResult, error) {
	client := &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
	resp, err := client.Call("logs.trim", map[string]any{"files": files})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r TrimResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func trimViaAgent(files []string) error {
	_, err := TrimSyslog(files)
	return err
}
