package controllers

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
)

type DhcpController struct {
	service *dhcp.Service
	orch    *network.Orchestrator
}

func NewDhcpController() *DhcpController {
	return &DhcpController{service: dhcp.New(), orch: network.NewOrchestrator()}
}

type leaseView struct {
	Address  string
	MAC      string
	Hostname string
	Until    string
	Pinned   bool
}

type reservationView struct {
	ID      uint
	Label   string
	MAC     string
	IP      string
	Waiting bool
	Stale   bool
}

func (c *DhcpController) Reserve(ctx contractshttp.Context) contractshttp.Response {

	label := strings.TrimSpace(ctx.Request().Input("label"))
	if label == "" {
		label = "Устройство"
	}
	mac, err := keagen.NormalizeMAC(ctx.Request().Input("mac"))
	if err != nil {
		setFlash(ctx, flashError, err.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
	}
	ip := strings.TrimSpace(ctx.Request().Input("ip"))
	if ip == "" {
		if seg := c.service.LANSegments(); len(seg) > 0 {
			if next, err := c.service.NextFreeReservationIP(seg[0].IPv4CIDR); err == nil {
				ip = next
			}
		}
	}
	lans := c.lans()
	if _, err := dhcp.Edit(lans, func(s *dhcp.Section) error {
		s.Reservations = append(s.Reservations, dhcp.SectionReservation{
			Label: label, MAC: mac, IP: ip, Subnet: dhcp.SubnetFor(lans, ip)})
		return nil
	}); err != nil {
		setFlash(ctx, flashError, err.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
	}
	msg := "Адрес " + ip + " закреплён. Он будет выдан при следующем обновлении аренды — чтобы применить сразу, перезагрузите устройство или переподключите его сетевой кабель."
	if keagen.IsRandomMAC(mac) {
		msg = "Похоже, устройство использует случайный аппаратный адрес (частая настройка Wi-Fi в Windows и телефонах). Закрепление сработает, только если отключить на устройстве смену адреса. " + msg
	}
	c.applyAndFlash(ctx, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
}

func (c *DhcpController) Unreserve(ctx contractshttp.Context) contractshttp.Response {
	id, err := strconv.ParseUint(ctx.Request().Input("id"), 10, 64)
	mac := ""
	for _, r := range c.service.Reservations() {
		if err == nil && uint64(r.ID) == id {
			mac = r.MAC
		}
	}
	if mac == "" {
		setFlash(ctx, flashError, "Закрепление не найдено.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
	}
	if _, err := dhcp.Edit(c.lans(), func(s *dhcp.Section) error {
		s.Reservations = slices.DeleteFunc(s.Reservations, func(r dhcp.SectionReservation) bool { return r.MAC == mac })
		return nil
	}); err != nil {
		setFlash(ctx, flashError, "Не удалось снять закрепление.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
	}
	c.applyAndFlash(ctx, "Закрепление снято. Устройство получит обычный адрес при следующем обновлении аренды.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/dhcp")
}

func (c *DhcpController) lans() []netip.Prefix {
	n, _ := network.ReadSection()
	return n.LANs()
}

func (c *DhcpController) applyAndFlash(ctx contractshttp.Context, msg string) {
	if _, err := c.orch.ApplyDHCP(ctx.Request().Ip()); err != nil {
		setFlash(ctx, flashError, "Настройки сохранены, но применить их не удалось: "+network.ErrText(err))
		return
	}
	setFlash(ctx, flashCode, msg)
}

func (c *DhcpController) Index(ctx contractshttp.Context) contractshttp.Response {
	plan := c.orch.DHCPPlan()
	view := map[string]any{
		"error":     takeFlash(ctx, flashError),
		"ok":        takeFlash(ctx, flashCode),
		"leaseTime": keagen.DefaultValidLifetime / 3600 / 24,
	}
	var notices []notice

	if len(plan.LANs) == 0 {
		notices = append(notices, notice{Level: "warn",
			Text: "Локальная сеть ещё не настроена. Назначьте карте роль «локальная сеть» на странице «Сеть» — после этого устройства офиса начнут получать адреса автоматически."})
		view["notices"] = notices
		return ctx.Response().View().Make("dhcp.tmpl", page(ctx, "DHCP", "dhcp", view))
	}

	state, leases, err := c.service.Leases()
	if err != nil {
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			notices = append(notices, notice{Level: "error",
				Text: "Системная служба недоступна — сведения о выданных адресах получить не удалось."})
		} else {
			notices = append(notices, notice{Level: "error", Text: network.ErrText(err)})
		}
		view["notices"] = notices
		return ctx.Response().View().Make("dhcp.tmpl", page(ctx, "DHCP", "dhcp", view))
	}

	switch state {
	case "missing":
		notices = append(notices, notice{Level: "error",
			Text: "Служба выдачи адресов не установлена на сервере. Устройства офиса не получат адреса автоматически."})
	case "inactive":
		notices = append(notices, notice{Level: "error",
			Text: "Служба выдачи адресов не работает. Проверьте, подключён ли кабель локальной сети, и примените настройки заново на странице «Сеть»."})
	}

	reservations := c.service.Reservations()
	pinnedMAC := map[string]string{}
	for _, r := range reservations {
		pinnedMAC[r.MAC] = r.IP
	}
	leaseByMAC := map[string]string{}
	rows := make([]leaseView, 0, len(leases))
	for _, l := range leases {
		leaseByMAC[l.MAC] = l.Address
		rows = append(rows, leaseView{
			Address: l.Address, MAC: l.MAC, Hostname: l.Hostname,
			Until:  l.Until.Format("02.01.2006 15:04"),
			Pinned: pinnedMAC[l.MAC] == l.Address,
		})
	}
	resViews := make([]reservationView, 0, len(reservations))
	inSegment := func(ip string) bool {
		for _, l := range plan.LANs {
			if _, ipnet, err := net.ParseCIDR(l.CIDR); err == nil {
				if parsed := net.ParseIP(ip); parsed != nil && ipnet.Contains(parsed) {
					return true
				}
			}
		}
		return false
	}
	for _, r := range reservations {
		stale := !inSegment(r.IP)
		waiting := !stale && leaseByMAC[r.MAC] != r.IP
		resViews = append(resViews, reservationView{
			ID: r.ID, Label: r.Label, MAC: r.MAC, IP: r.IP,
			Waiting: waiting, Stale: stale,
		})
		if stale {
			notices = append(notices, notice{Level: "warn",
				Text: "Закрепление «" + r.Label + "» (" + r.IP + ") не подходит текущим настройкам локальной сети — адрес из прежней подсети. Снимите закрепление и создайте новое."})
		}
	}
	view["reservations"] = resViews
	if seg := c.service.LANSegments(); len(seg) > 0 {
		if next, err := c.service.NextFreeReservationIP(seg[0].IPv4CIDR); err == nil {
			view["suggestIP"] = next
		}
	}
	stats := c.service.PoolStats(plan, leases)
	for _, st := range stats {
		if st.Percent >= dhcp.PoolWarnPercent {
			notices = append(notices, notice{Level: "warn",
				Text: fmt.Sprintf("Свободных адресов почти не осталось: занято %d из %d в сегменте %s. Новые устройства могут не получить адрес — возможно, стоит уменьшить кол-во устройств в офисе.",
					st.Used, st.Size, st.CIDR)})
		}
	}

	view["leases"] = rows
	view["pools"] = stats
	view["service"] = state
	view["notices"] = notices
	return ctx.Response().View().Make("dhcp.tmpl", page(ctx, "DHCP", "dhcp", view))
}
