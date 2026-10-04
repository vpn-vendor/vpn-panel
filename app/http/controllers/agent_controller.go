package controllers

import (
	"errors"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

type AgentController struct{}

func NewAgentController() *AgentController { return &AgentController{} }

func (c *AgentController) Ping(ctx contractshttp.Context) contractshttp.Response {
	client := &agentrpc.Client{
		SocketPath: facades.Config().GetString("agent.socket"),
	}

	resp, err := client.Call("system.ping", map[string]any{})
	if err != nil {
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {

			return ctx.Response().Json(contractshttp.StatusServiceUnavailable, contractshttp.Json{
				"agent":  "unreachable",
				"stage":  terr.Op,
				"detail": terr.Error(),
				"socket": client.SocketPath,
			})
		}
		return ctx.Response().Json(contractshttp.StatusInternalServerError, contractshttp.Json{
			"agent":  "unreachable",
			"detail": err.Error(),
		})
	}

	if resp.Error != nil {

		return ctx.Response().Json(contractshttp.StatusBadGateway, contractshttp.Json{
			"agent":    "error",
			"response": resp,
		})
	}
	return ctx.Response().Success().Json(contractshttp.Json{
		"agent":    "ok",
		"response": resp,
	})
}
