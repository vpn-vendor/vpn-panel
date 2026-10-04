package controllers

import (
	"errors"
	"strconv"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
)

type NetworkController struct {
	orch    *network.Orchestrator
	service *network.Service
}

func NewNetworkController() *NetworkController {
	orch := network.NewOrchestrator()
	return &NetworkController{orch: orch, service: orch.Network()}
}

type ifaceView struct {
	Name      string
	MAC       string
	State     string
	Addresses []string
	Role      string
	CIDR      string
	WANMethod string
	Gateway   string
	DNS       string

	PPPoEUser string

	PPPoESaved bool

	VLAN      string
	VLANIface string
}

func (c *NetworkController) Status(ctx contractshttp.Context) contractshttp.Response {
	view := map[string]any{
		"agentDown":   false,
		"methodError": "",
		"error":       takeFlash(ctx, flashError),
		"ok":          takeFlash(ctx, flashCode),
	}

	st, err := c.service.Status()
	switch err {
	case nil:
		roles := c.service.Roles()
		own := c.service.OwnInterfaces()
		rows := make([]ifaceView, 0, len(st.Interfaces))
		for _, i := range st.Interfaces {

			if i.Loopback || own[i.Name] {
				continue
			}
			v := ifaceView{Name: i.Name, MAC: i.MAC, State: i.State,
				Addresses: i.Addresses, Role: network.RoleUnused}
			if r, ok := roles[i.Name]; ok {
				v.Role, v.CIDR = r.Role, r.IPv4CIDR
				v.WANMethod, v.Gateway, v.DNS = r.IPv4Method, r.IPv4Gateway, r.IPv4DNS
				v.PPPoEUser = r.PPPoEUsername
				if r.VLAN > 0 {
					v.VLAN = strconv.Itoa(r.VLAN)
					v.VLANIface = netplangen.LinkIface(r.Name, r.VLAN)
				}

				v.PPPoESaved = r.IPv4Method == netplangen.MethodPPPoE && r.PPPoEUsername != ""
			}
			if v.Role == network.RoleUnused || v.WANMethod == "" {
				v.WANMethod = "dhcp"
			}
			rows = append(rows, v)
		}
		view["ifaces"] = rows

		for _, r := range rows {
			if r.Role == netplangen.RoleWAN {
				rr := r
				view["wan"] = rr
				break
			}
		}
		view["routes"] = st.DefaultRoutes

		var notices []notice
		hasWAN, hasLAN := false, false
		for _, r := range rows {
			switch r.Role {
			case "wan":
				hasWAN = true
			case "lan":
				hasLAN = true

				if r.State != "UP" {
					notices = append(notices, notice{Level: "warn",
						Text: "К карте «" + r.Name + "» (локальная сеть) не подключён кабель. Настройки можно применить сейчас — всё заработает автоматически, как только кабель будет подключён."})
				}
			}
		}
		if !hasWAN || !hasLAN {
			notices = append(notices, notice{Level: "info",
				Text: "Назначьте одной карте роль «интернет», а другой — «локальная сеть»: после применения устройства офиса получат интернет и адреса автоматически, а панель останется доступна только из локальной сети."})
		}
		view["notices"] = notices
	default:
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			view["agentDown"] = true
		} else {
			view["methodError"] = network.ErrText(err)
		}
	}
	return ctx.Response().View().Make("network.tmpl", page(ctx, "Сеть", "network", view))
}

var errNoRoles = errors.New("нет ни одной роли")

func (c *NetworkController) Apply(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	st, err := c.service.Status()
	if err != nil {
		setFlash(ctx, flashError, "Системная служба недоступна — применить нельзя.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network")
	}

	var secrets network.ApplySecrets

	own := c.service.OwnInterfaces()
	var inputs []network.RoleInput
	known := map[string]bool{}
	for _, i := range st.Interfaces {
		if i.Loopback {
			continue
		}
		known[i.Name] = true
		if own[i.Name] {
			continue
		}
		role := ctx.Request().Input("role_" + i.Name)
		if role == "" {
			continue
		}
		inputs = append(inputs, network.RoleInput{
			Name: i.Name, MAC: i.MAC, Role: role,
			CIDR:          ctx.Request().Input("cidr_" + i.Name),
			WANMethod:     ctx.Request().Input("wanmethod_" + i.Name),
			Gateway:       ctx.Request().Input("gateway_" + i.Name),
			DNS:           ctx.Request().Input("dns_" + i.Name),
			PPPoEUsername: ctx.Request().Input("pppoeuser_" + i.Name),
			VLAN:          ctx.Request().Input("vlan_" + i.Name),
		})

		if pw := ctx.Request().Input("pppoepass_" + i.Name); pw != "" {
			secrets.PPPoEPassword = pw
		}
	}

	var editErr error
	outcome, err := c.orch.Change(ip, st, secrets, func() error {
		_, editErr = network.Edit(func(s *network.Section) error {
			for _, in := range inputs {
				if err := s.SetRole(in); err != nil {
					return errors.New("роль для " + in.Name + " не сохранена: " + err.Error())
				}
			}
			p := s.Plan()
			if len(p.Interfaces) == 0 {
				return errNoRoles
			}
			return p.Validate(known)
		})
		return editErr
	})
	if editErr != nil {
		text := editErr.Error()
		if errors.Is(editErr, errNoRoles) {
			text = "Назначьте хотя бы один интерфейс (интернет или локальная сеть)."
		}
		setFlash(ctx, flashError, text)
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network")
	}
	if err != nil {
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network")
	}
	if outcome.AwaitingConfirm {
		setFlash(ctx, flashReturn, "/network")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network/confirming")
	}
	setFlash(ctx, flashCode, outcome.Message)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/network")
}

func (c *NetworkController) Confirming(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().View().Make("network_confirming.tmpl",
		page(ctx, "Проверка связи", "network", map[string]any{
			"timeout": c.service.ConfirmTimeout(),
		}))
}

func (c *NetworkController) Confirm(ctx contractshttp.Context) contractshttp.Response {
	back := returnPath(ctx)
	msg, err := c.orch.Confirm(ctx.Request().Ip())
	if err != nil {
		setFlash(ctx, flashError, "Изменения не подтверждены и откатились.")
		return ctx.Response().Redirect(contractshttp.StatusFound, back)
	}
	setFlash(ctx, flashCode, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, back)
}

func (c *NetworkController) Cancel(ctx contractshttp.Context) contractshttp.Response {
	back := returnPath(ctx)
	c.orch.Cancel(ctx.Request().Ip())
	setFlash(ctx, flashCode, "Изменения откатились — сеть как прежде.")
	return ctx.Response().Redirect(contractshttp.StatusFound, back)
}

func returnPath(ctx contractshttp.Context) string {
	switch takeFlash(ctx, flashReturn) {
	case "/security":
		return "/security"
	default:
		return "/network"
	}
}

func (c *NetworkController) Suggest(ctx contractshttp.Context) contractshttp.Response {
	rawIP := ctx.Request().Input("ip")
	gateway := ctx.Request().Input("gateway")
	maskField := ctx.Request().Input("mask")

	addr, prefix, _ := netplangen.ParseAddrField(rawIP)
	if addr == "" {
		addr = rawIP
	}

	res := map[string]any{}
	if prefix < 0 && maskField != "" {
		if p, ok := netplangen.MaskToPrefix(maskField); ok {
			prefix = p
		}
	}
	if prefix < 0 && addr != "" && gateway != "" {
		if p, reason, ok := netplangen.SuggestPrefix(addr, gateway); ok {
			prefix = p
			res["suggestReason"] = reason
			res["suggested"] = true
		}
	}
	if prefix >= 0 {
		res["prefix"] = prefix
		if m, ok := netplangen.PrefixToMask(prefix); ok {
			res["mask"] = m
		}
		if gateway != "" && addr != "" && !netplangen.GatewayConsistent(addr, prefix, gateway) {
			res["gatewayWarning"] = "Шлюз вне вашей подсети при этой маске — обычно это опечатка. Применить всё равно можно."
		}
	}
	return ctx.Response().Json(contractshttp.StatusOK, res)
}
