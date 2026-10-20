package controllers

import (
	"errors"
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
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

	CloneMAC string

	SpeedMbit int
	Provider  bool
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
				v.PPPoEUser, v.CloneMAC = r.PPPoEUsername, r.CloneMAC
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
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Name)
		}
		provider := map[string]bool{}
		for _, r := range st.DefaultRoutes {
			provider[r.Dev] = true
		}
		speed := map[string]int{}
		for _, p := range sysinfo.Ports(names) {
			if p.SpeedKnown && p.SpeedMbit > 0 {
				speed[p.Name] = p.SpeedMbit
			}
		}
		for i := range rows {
			rows[i].SpeedMbit, rows[i].Provider = speed[rows[i].Name], provider[rows[i].Name]
		}
		view["ifaces"] = rows
		view["hero"] = networkHero(rows, st.DefaultRoutes)
		if w, ok := view["wan"].(ifaceView); ok {
			w.SpeedMbit, w.Provider = speed[w.Name], provider[w.Name]
			view["wan"] = w
			view["wanMethods"] = networkMethods(w)
		}

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

		var lans, cards []string
		for _, r := range rows {
			if r.Role == "lan" {
				lans = append(lans, r.Name)
			}
			if r.Role != "" {
				cards = append(cards, r.Name)
			}
		}
		if len(lans) > 0 {

			if msg, warn, err := system.New().DHCPCheck(lans, cards, nil); err == nil {
				if msg != "" {
					notices = append(notices, notice{Level: "error", Text: msg})
				} else if warn != "" {
					notices = append(notices, notice{Level: "warn", Text: warn})
				}
			}
		}
		if around, err := system.New().Surroundings(); err == nil {
			applied := len(c.service.AppliedLANs()) > 0 && c.service.HasWANAndLAN()
			notices = append(notices, networkNotices(around, applied)...)
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
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/network"))
	}

	if msg := system.New().Refusal(string(settings.SectionNetwork)); msg != "" {
		setFlash(ctx, flashError, msg)
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/network"))
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
			CloneMAC:      ctx.Request().Input("clonemac_" + i.Name),
			CloneSet:      ctx.Request().Input("clonemac_set_"+i.Name) == "1",
		})

		if ctx.Request().Input("clonemac_reset_"+i.Name) == "1" {
			inputs[len(inputs)-1].CloneMAC, inputs[len(inputs)-1].CloneSet = "", true
		}

		if pw := ctx.Request().Input("pppoepass_" + i.Name); pw != "" {
			secrets.PPPoEPassword = pw
		} else if ctx.Request().Input("pppoepass_source_"+i.Name) == "legacy" {

			secrets.PPPoESource = "legacy"
		}
	}

	var editErr error

	wizard := fromWizard(ctx)
	change := c.orch.Change
	if wizard {
		change = c.orch.ChangeInWindow

		secrets.Takeover = setup.TakeoverConsent()
	}
	outcome, err := change(ip, st, secrets, func() error {
		_, editErr = network.Edit(func(s *network.Section) error {
			before := map[string]string{}
			for _, i := range s.Interfaces {
				before[i.Name] = i.CloneMAC
			}
			for _, in := range inputs {
				if err := s.SetRole(in); err != nil {
					return errors.New("роль для " + in.Name + " не сохранена: " + err.Error())
				}
			}
			if err := c.cloneConflict(s, before, st); err != nil {
				return err
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
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/network"))
	}
	if err != nil {
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/network"))
	}
	if wizard && outcome.AwaitingConfirm {
		c.watchWizard(ip, st, inputs)
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/applying")
	}

	setup.ClearDrafts()
	if outcome.AwaitingConfirm {
		setFlash(ctx, flashReturn, landing(ctx, "/network"))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/network/confirming")
	}
	setFlash(ctx, flashCode, outcome.Message)
	return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/network"))
}

func (c *NetworkController) cloneConflict(s *network.Section, before map[string]string, st *netstatus.Status) error {
	var neigh []netstatus.Neighbor
	asked := false
	for _, i := range s.Interfaces {
		if i.CloneMAC == "" || i.CloneMAC == before[i.Name] {
			continue
		}
		if !asked {

			neigh, _ = c.service.Neighbors()
			asked = true
		}
		if text := network.CloneConflict(i.CloneMAC, i.Name, st, neigh); text != "" {
			return errors.New(text)
		}
	}
	return nil
}

func (c *NetworkController) watchWizard(ip string, st *netstatus.Status, inputs []network.RoleInput) {
	dev, method := "", ""
	for _, in := range inputs {
		if in.Role == netplangen.RoleWAN {
			dev, method = in.Name, in.WANMethod
		}
	}
	if method == netplangen.MethodPPPoE {
		dev = netplangen.IfacePPPoE
	}
	network.StartWizardWatch(network.WatchPlan{
		Method:   method,
		Window:   time.Duration(c.service.ConfirmTimeout()) * time.Second,
		NeedSeen: c.service.GuardNeeded(ip, c.service.BuildPlan(), st),
		Probe: func() bool {
			now, err := c.service.Status()
			return err == nil && network.ProviderUp(now, dev)
		},
		Confirm: func() error {
			if _, err := c.orch.Confirm(ip); err != nil {
				return err
			}
			setup.ClearDrafts()
			return nil
		},
		Cancel: func() { c.orch.Cancel(ip) },
	})
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
	case "/setup":
		return "/setup"
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
