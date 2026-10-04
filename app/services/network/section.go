package network

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const (
	ConfirmTimeoutMin = 15
	ConfirmTimeoutMax = 900
)

type Section struct {
	ConfirmTimeoutSec int                `json:"confirm_timeout_sec" setting:"network.confirm_timeout_sec"`
	Interfaces        []SectionInterface `json:"interfaces" table:"interfaces"`
}

type SectionInterface struct {
	Name          string `json:"name" ref:"nic"`
	MAC           string `json:"mac" ref:"mac"`
	Role          string `json:"role"`
	IPv4Method    string `json:"ipv4_method"`
	IPv4CIDR      string `json:"ipv4_cidr"`
	IPv4Gateway   string `json:"ipv4_gateway"`
	IPv4DNS       string `json:"ipv4_dns"`
	WANMetric     uint   `json:"wan_metric"`
	PPPoEUsername string `json:"pppoe_username"`
	VLAN          int    `json:"vlan"`
}

func ReadSection() (Section, error) {
	var rows []models.Interface
	if err := facades.Orm().Query().OrderBy("id").Find(&rows); err != nil {
		return Section{}, err
	}
	out := Section{ConfirmTimeoutSec: New().ConfirmTimeout(), Interfaces: []SectionInterface{}}
	for _, r := range rows {
		if ProductIface(r.Name) {
			continue
		}

		method := r.IPv4Method
		switch {
		case method != "":
		case r.Role == netplangen.RoleWAN:
			method = netplangen.MethodDHCP
		case r.Role == netplangen.RoleLAN:
			method = netplangen.MethodStatic
		}
		out.Interfaces = append(out.Interfaces, SectionInterface{
			Name: r.Name, MAC: r.MAC, Role: r.Role, IPv4Method: method, IPv4CIDR: r.IPv4CIDR,
			IPv4Gateway: r.IPv4Gateway, IPv4DNS: r.IPv4DNS, WANMetric: r.WANMetric,
			PPPoEUsername: r.PPPoEUsername, VLAN: r.VLAN,
		})
	}
	return out, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	if v.ConfirmTimeoutSec < ConfirmTimeoutMin || v.ConfirmTimeoutSec > ConfirmTimeoutMax {
		errs.Add("confirm_timeout_sec", "окно подтверждения — от %d до %d секунд", ConfirmTimeoutMin, ConfirmTimeoutMax)
	}
	links := map[string]bool{}
	for _, i := range v.Interfaces {

		if link := netplangen.LinkIface(i.Name, i.VLAN); i.Role == netplangen.RoleWAN && link != i.Name {
			links[link] = true
		}
	}
	for n, i := range v.Interfaces {
		key := ""
		if netplangen.ValidIfaceName(i.Name) {
			key = i.Name
		}
		path := fielderr.Row("interfaces", n, key)
		if ProductIface(i.Name) || links[i.Name] {
			errs.Add(fielderr.Join(path, "name"), "интерфейс %q создаёт сам продукт — роль ему не назначается", i.Name)
			continue
		}
		errs.Under(path, validateInterface(i))
	}
	if len(errs) == 0 {
		if plan := sectionPlan(v); len(plan.Interfaces) > 0 {
			if err := plan.Validate(nil); err != nil {
				errs.Add("interfaces", "%s", err.Error())
			}
		}
	}
	return errs
}

func validateInterface(i SectionInterface) fielderr.List {
	var errs fielderr.List
	if !netplangen.ValidIfaceName(i.Name) {
		errs.Add("name", "недопустимое имя карты %q", i.Name)
	}
	if i.MAC != "" && !keagen.ValidMAC(i.MAC) {
		errs.Add("mac", "неверный аппаратный адрес %q (вид a4:bb:6d:1f:22:90)", i.MAC)
	}

	var allowed map[string]bool
	switch i.Role {
	case netplangen.RoleWAN:
		switch i.IPv4Method {
		case netplangen.MethodDHCP:
			allowed = fields("vlan")
		case netplangen.MethodStatic:
			allowed = fields("cidr", "gateway", "dns", "vlan")
		case netplangen.MethodPPPoE:
			allowed = fields("pppoe", "vlan")
			if !netplangen.ValidPPPoEUsername(i.PPPoEUsername) {
				errs.Add("pppoe_username", "логин PPPoE — латинские буквы, цифры и . _ @ + -, до 128 знаков")
			}
		default:
			errs.Add("ipv4_method", "способ подключения к интернету — dhcp, static или pppoe")
		}
		if i.VLAN != 0 && (i.VLAN < 1 || i.VLAN > netplangen.MaxVLANID) {
			errs.Add("vlan", "тег VLAN — от 1 до %d", netplangen.MaxVLANID)
		}
	case netplangen.RoleLAN:
		allowed = fields("cidr")
		if i.IPv4Method != netplangen.MethodStatic {
			errs.Add("ipv4_method", "локальной сети нужен статический адрес")
		}
	case RoleUnused:
		allowed = fields()
		if i.IPv4Method != "" {
			errs.Add("ipv4_method", "у неиспользуемой карты нет способа подключения")
		}
	default:
		errs.Add("role", "роль карты — wan, lan или unused")
		return errs
	}
	for _, f := range []struct{ key, path, val string }{
		{"cidr", "ipv4_cidr", i.IPv4CIDR}, {"gateway", "ipv4_gateway", i.IPv4Gateway},
		{"dns", "ipv4_dns", i.IPv4DNS}, {"pppoe", "pppoe_username", i.PPPoEUsername},
	} {
		if f.val != "" && !allowed[f.key] {
			errs.Add(f.path, "поле не используется при такой роли и способе подключения")
		}
	}
	if i.VLAN != 0 && !allowed["vlan"] {
		errs.Add("vlan", "тег VLAN задаётся только у подключения к интернету")
	}
	return errs
}

func fields(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func sectionPlan(v Section) netplangen.Plan {
	var p netplangen.Plan
	for _, r := range v.Interfaces {
		if r.Role != netplangen.RoleWAN && r.Role != netplangen.RoleLAN {
			continue
		}
		pi := netplangen.PlanInterface{Name: r.Name, Role: r.Role, Method: r.IPv4Method,
			CIDR: r.IPv4CIDR, Metric: int(r.WANMetric)}
		if r.Role == netplangen.RoleWAN {
			pi.VLAN = r.VLAN
			switch r.IPv4Method {
			case netplangen.MethodStatic:
				pi.Gateway = r.IPv4Gateway
				pi.DNS = splitDNS(r.IPv4DNS)
			case netplangen.MethodPPPoE:
				pi.Username = r.PPPoEUsername
			}
		}
		p.Interfaces = append(p.Interfaces, pi)
	}
	return p
}

func splitDNS(s string) []string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (v Section) LANs() []netip.Prefix {
	var out []netip.Prefix
	for _, i := range v.Interfaces {
		if i.Role != netplangen.RoleLAN {
			continue
		}
		if p, err := netip.ParsePrefix(i.IPv4CIDR); err == nil && p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func ProductIface(name string) bool { return slices.Contains(productIfaces, name) }

var productIfaces = append(vpnproto.Ifaces(), qosgen.IFBDevice, qosgen.IFBTunnelDevice, netplangen.IfacePPPoE)

func (v *Section) SetRole(in RoleInput) error {
	row := SectionInterface{Name: in.Name, WANMetric: 100}
	idx := -1
	for i := range v.Interfaces {
		if v.Interfaces[i].Name == in.Name {
			row, idx = v.Interfaces[i], i
		}
	}
	row.MAC, row.Role = in.MAC, in.Role
	row.IPv4CIDR, row.IPv4Gateway, row.IPv4DNS, row.PPPoEUsername, row.VLAN = in.CIDR, "", "", "", 0
	switch in.Role {
	case netplangen.RoleWAN:

		if t := strings.TrimSpace(in.VLAN); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil {
				return fmt.Errorf("тег VLAN должен быть числом от 1 до %d", netplangen.MaxVLANID)
			}
			row.VLAN = n
		}
		row.IPv4Method = in.WANMethod
		if row.IPv4Method == "" {
			row.IPv4Method = netplangen.MethodDHCP
		}
		switch row.IPv4Method {
		case netplangen.MethodDHCP:
			row.IPv4CIDR = ""
		case netplangen.MethodStatic:
			row.IPv4Gateway, row.IPv4DNS = in.Gateway, in.DNS
		case netplangen.MethodPPPoE:

			row.IPv4CIDR, row.PPPoEUsername = "", strings.TrimSpace(in.PPPoEUsername)
		}
	case netplangen.RoleLAN:
		row.IPv4Method = netplangen.MethodStatic
	case RoleUnused:
		row.IPv4Method, row.IPv4CIDR = "", ""
	}
	if idx >= 0 {
		v.Interfaces[idx] = row
	} else {
		v.Interfaces = append(v.Interfaces, row)
	}
	return nil
}

func ApplySection(cur, want Section) error {
	added, changed, removed := change.Rows(cur.Interfaces, want.Interfaces, func(i SectionInterface) string { return i.Name })
	now := time.Now()
	return facades.Orm().Transaction(func(tx orm.Query) error {
		if err := settings.WriteChangedIn(tx, cur, want); err != nil {
			return err
		}
		for _, i := range removed {
			if _, err := tx.Where("name", i.Name).Delete(&models.Interface{}); err != nil {
				return err
			}
		}
		for _, i := range changed {
			if _, err := tx.Model(&models.Interface{}).Where("name", i.Name).Update(map[string]any{
				"mac": i.MAC, "role": i.Role, "ipv4_method": i.IPv4Method, "ipv4_cidr": i.IPv4CIDR,
				"ipv4_gateway": i.IPv4Gateway, "ipv4_dns": i.IPv4DNS, "wan_metric": i.WANMetric,
				"pppoe_username": i.PPPoEUsername, "vlan": i.VLAN, "updated_at": now}); err != nil {
				return err
			}
		}
		for _, i := range added {
			if err := tx.Create(&models.Interface{Name: i.Name, MAC: i.MAC, Role: i.Role, IPv4Method: i.IPv4Method,
				IPv4CIDR: i.IPv4CIDR, IPv4Gateway: i.IPv4Gateway, IPv4DNS: i.IPv4DNS, WANMetric: i.WANMetric,
				PPPoEUsername: i.PPPoEUsername, VLAN: i.VLAN, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
		return nil
	})
}

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}

func (v Section) Plan() netplangen.Plan { return sectionPlan(v) }
