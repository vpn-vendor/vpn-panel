package network

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/listen"
	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/httpserve"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

const RoleUnused = "unused"

const SettingConfirmTimeout = "network.confirm_timeout_sec"

const SettingAppliedLANs = "network.applied_lans"

const defaultConfirmTimeout = 120

const applyResponseTimeout = 90 * time.Second

const pendingGrace = 15 * time.Second

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Status() (*netstatus.Status, error) {
	resp, err := s.client().Call("network.status", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var st netstatus.Status
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Service) Roles() map[string]models.Interface {
	var rows []models.Interface
	_ = facades.Orm().Query().Find(&rows)
	out := make(map[string]models.Interface, len(rows))
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

type RoleInput struct {
	Name, MAC, Role string
	CIDR            string
	WANMethod       string
	Gateway         string
	DNS             string

	PPPoEUsername string

	VLAN string
}

func (s *Service) OwnInterfaces() map[string]bool {
	own := map[string]bool{}
	for _, n := range productIfaces {
		own[n] = true
	}
	for _, r := range s.Roles() {
		if r.Role != netplangen.RoleWAN {
			continue
		}
		if link := netplangen.LinkIface(r.Name, r.VLAN); link != r.Name {
			own[link] = true
		}
	}
	return own
}

func (s *Service) BuildPlan() netplangen.Plan {
	plan := netplangen.Plan{IPv6: security.New().Load().IPv6}
	for _, r := range s.Roles() {
		if r.Role != netplangen.RoleWAN && r.Role != netplangen.RoleLAN {
			continue
		}
		pi := netplangen.PlanInterface{
			Name: r.Name, Role: r.Role, Method: r.IPv4Method,
			CIDR: r.IPv4CIDR, Metric: int(r.WANMetric),
		}
		if r.Role == netplangen.RoleWAN && r.IPv4Method == netplangen.MethodStatic {
			pi.Gateway = r.IPv4Gateway
			for _, d := range strings.Split(r.IPv4DNS, ",") {
				if d = strings.TrimSpace(d); d != "" {
					pi.DNS = append(pi.DNS, d)
				}
			}
		}
		if r.Role == netplangen.RoleWAN && r.IPv4Method == netplangen.MethodPPPoE {
			pi.Username = r.PPPoEUsername
		}
		if r.Role == netplangen.RoleWAN {
			pi.VLAN = r.VLAN
		}
		plan.Interfaces = append(plan.Interfaces, pi)
	}
	return plan
}

func (s *Service) GuardNeeded(clientIP string, plan netplangen.Plan, st *netstatus.Status) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.IsLoopback() || st == nil {
		return false
	}
	planned := map[string]netplangen.PlanInterface{}
	for _, p := range plan.Interfaces {
		planned[p.Name] = p
	}
	for _, iface := range st.Interfaces {
		if !reachedVia(iface.Addresses, ip) {
			continue
		}

		p, ok := planned[iface.Name]
		if !ok {
			return true
		}
		if p.Role != netplangen.RoleLAN {
			return true
		}
		if !addressKept(iface.Addresses, p.CIDR) {
			return true
		}
	}
	return false
}

func reachedVia(addresses []string, ip net.IP) bool {
	for _, cidr := range addresses {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func addressKept(current []string, planned string) bool {
	pip, pnet, err := net.ParseCIDR(planned)
	if err != nil {
		return false
	}
	for _, cidr := range current {
		cip, cnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if cip.Equal(pip) && cnet.String() == pnet.String() {
			return true
		}
	}
	return false
}

func (s *Service) ConfirmTimeout() int {
	if v, err := strconv.Atoi(settings.Get(SettingConfirmTimeout)); err == nil && v >= ConfirmTimeoutMin && v <= ConfirmTimeoutMax {
		return v
	}
	return defaultConfirmTimeout
}

type ApplySecrets struct {
	PPPoEPassword string
}

type ApplyResult struct {
	Changed    bool
	State      string
	TimeoutSec int
}

func (s *Service) Apply(plan netplangen.Plan, guard bool, firewall *nftgen.FirewallPlan, sec ApplySecrets) (*ApplyResult, error) {
	timeout := s.ConfirmTimeout()
	params := map[string]any{"plan": plan, "guard": guard, "timeout_sec": timeout}
	if firewall != nil {
		params["firewall"] = firewall
	}

	if sec.PPPoEPassword != "" {
		params["pppoe_password"] = sec.PPPoEPassword
	}
	resp, err := s.client().CallWithin("network.apply", params, applyResponseTimeout)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Changed    bool   `json:"changed"`
		State      string `json:"state"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	switch r.State {
	case "awaiting_confirm":
		if m := listen.Current(); m != nil {
			m.SetPending(planLANs(plan), time.Duration(r.TimeoutSec)*time.Second+pendingGrace)
		}
	case "applied":
		s.markApplied(plan)
	}
	return &ApplyResult{Changed: r.Changed, State: r.State, TimeoutSec: r.TimeoutSec}, nil
}

func (s *Service) Confirm() error {
	if err := s.simpleCall("network.confirm"); err != nil {
		s.clearPending()
		return err
	}
	s.markApplied(s.BuildPlan())
	return nil
}

func (s *Service) Cancel() error {
	resp, err := s.client().CallWithin("network.cancel", map[string]any{}, applyResponseTimeout)
	if err == nil && resp.Error != nil {
		err = resp.Error
	}
	s.clearPending()
	return err
}

func (s *Service) AppliedLANs() []string {
	raw := settings.Get(SettingAppliedLANs)
	if raw == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

func planLANs(plan netplangen.Plan) []string {
	var out []string
	for _, i := range plan.Interfaces {
		if i.Role == netplangen.RoleLAN && i.CIDR != "" {
			out = append(out, i.CIDR)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) markApplied(plan netplangen.Plan) {
	raw, _ := json.Marshal(planLANs(plan))
	if err := settings.Set(SettingAppliedLANs, string(raw)); err != nil {
		log.Printf("network: %v", err)
	}
	s.clearPending()
}

func (s *Service) clearPending() {
	if m := listen.Current(); m != nil {
		m.ClearPending()
	}
}

func (s *Service) simpleCall(method string) error {
	resp, err := s.client().Call(method, map[string]any{})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

func (s *Service) BuildFirewall() nftgen.FirewallPlan {
	st := security.New().Load()
	fp := nftgen.FirewallPlan{HiddenMode: st.HiddenMode, IPv6: st.IPv6, Panel: panelLimits()}
	for _, r := range s.Roles() {
		switch r.Role {
		case netplangen.RoleWAN:
			fp.WANs = append(fp.WANs,
				netplangen.EffectiveWAN(netplangen.LinkIface(r.Name, r.VLAN), r.IPv4Method))
		case netplangen.RoleLAN:
			fp.LANs = append(fp.LANs, nftgen.FirewallLAN{Name: r.Name, CIDR: r.IPv4CIDR})
		}
	}
	return fp
}

func panelLimits() *nftgen.FirewallPanel {
	config := facades.Config()
	var ports []int
	for _, key := range []string{"http.tls.port", "http.redirect_port"} {
		raw := config.GetString(key)
		if raw == "" {
			continue
		}
		port, err := strconv.Atoi(raw)
		if err != nil || port <= 0 || port > 65535 {
			return nil
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil
	}

	return &nftgen.FirewallPanel{Ports: ports, PerSourceConns: httpserve.KernelPerAddressConns,
		TotalNewPerSecond: nftgen.PanelTotalNewPerSecond(runtime.GOMAXPROCS(0))}
}

func (s *Service) HasWANAndLAN() bool {
	fp := s.BuildFirewall()
	return len(fp.WANs) > 0 && len(fp.LANs) > 0
}

func (s *Service) ApplyFirewall(fp nftgen.FirewallPlan) (bool, string, error) {
	resp, err := s.client().Call("firewall.apply", map[string]any{"plan": fp})
	if err != nil {
		return false, "", err
	}
	if resp.Error != nil {
		return false, "", resp.Error
	}
	var r struct {
		Changed bool   `json:"changed"`
		UFW     string `json:"ufw"`
	}
	_ = json.Unmarshal(resp.Result, &r)
	return r.Changed, r.UFW, nil
}

func (s *Service) FirewallIfReady() *nftgen.FirewallPlan {
	fp := s.BuildFirewall()
	if len(fp.WANs) == 0 || len(fp.LANs) == 0 {
		return nil
	}
	return &fp
}

type LockoutError struct{ Text string }

func (e *LockoutError) Error() string { return e.Text }

func ErrText(err error) string {
	var terr *agentrpc.TransportError
	if errors.As(err, &terr) {
		return "Системная служба недоступна — применить нельзя."
	}
	var lerr *LockoutError
	if errors.As(err, &lerr) {
		return lerr.Text
	}

	var rej *change.Rejected
	if errors.As(err, &rej) {
		return rej.Error()
	}
	var merr *agentrpc.ErrorObject
	if errors.As(err, &merr) {
		if detail, ok := merr.Data["detail"]; ok && detail != "" {
			facades.Log().Warningf("agent error %d: %s (detail: %v)", merr.Code, merr.Message, detail)
		}
		if merr.Code < 0 {
			facades.Log().Errorf("agent protocol error %d: %s", merr.Code, merr.Message)
		}
		return agentrpc.Human(err)
	}
	return "Не удалось применить настройки."
}

func (s *Service) LockoutRisk(clientIP string, plan netplangen.Plan, st *netstatus.Status) string {
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.IsLoopback() || st == nil {
		return ""
	}
	byName := map[string]netplangen.PlanInterface{}
	for _, p := range plan.Interfaces {
		byName[p.Name] = p
	}
	for _, iface := range st.Interfaces {
		p, inPlan := byName[iface.Name]
		if !inPlan {
			continue
		}
		for _, cidr := range iface.Addresses {
			_, cur, err := net.ParseCIDR(cidr)
			if err != nil || !cur.Contains(ip) {
				continue
			}
			switch p.Role {
			case netplangen.RoleWAN:
				return "Вы подключены к панели через карту «" + iface.Name + "», а назначаете ей роль «интернет»: после применения панель на этой карте недоступна по правилам защиты, и изменения откатятся. Примените настройки из локальной сети или с самого сервера."
			case netplangen.RoleLAN:
				if _, newNet, err := net.ParseCIDR(p.CIDR); err == nil && !newNet.Contains(ip) {
					return "Вы подключены к карте «" + iface.Name + "» из сети " + cur.String() + ", а назначаете ей адрес " + p.CIDR + ": после применения панель станет недоступна с вашего компьютера, и изменения откатятся. Укажите адрес из текущей сети " + cur.String() + " либо примените настройки с самого сервера."
				}
			}
		}
	}
	return ""
}

func (s *Service) Audit(event, ip, details string) {
	securitylog.Record(models.AuthEvent{
		Event: event, IP: ip, Details: details, OccurredAt: time.Now(),
	})
}
