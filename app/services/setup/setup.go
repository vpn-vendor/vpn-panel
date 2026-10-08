package setup

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	vpnsvc "github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

const (
	SettingWANCard  = "setup.wan_card"
	SettingLANCard  = "setup.lan_card"
	SettingSkipped  = "setup.skipped"
	SettingFinished = "setup.finished"
)

type Card struct {
	Name      string
	MAC       string
	Up        bool
	Addresses []string
	HasRoute  bool
	Role      string
}

type Facts struct {
	HasAdmin  bool
	AgentDown bool
	Cards     []Card
	WANDraft  string
	LANDraft  string

	RolesApplied bool
	WANName      string
	LANName      string
	LANCIDR      string

	WANMethod, WANCIDR, WANGateway, WANDNS, PPPoEUser, VLAN string

	MeasuredDown, MeasuredUp int

	ConfirmTimeout int

	Internet    string
	SpeedSet    bool
	ChannelSet  bool
	ChannelUp   bool
	Profiles    int
	ProfileSlug string
	ProfileName string
	Leases      int
	Skipped     map[string]bool
	Finished    bool
}

type Deps struct {
	Paths func() []pathmon.Snapshot
}

func Collect(d Deps) Facts {
	f := Facts{Skipped: skipped(), Finished: settings.Get(SettingFinished) == "1"}
	f.HasAdmin = auth.New().HasUsers()
	if !f.HasAdmin {
		return f
	}
	f.WANDraft, f.LANDraft = settings.Get(SettingWANCard), settings.Get(SettingLANCard)

	ns := network.New()
	roles := ns.Roles()
	st, err := ns.Status()
	if err != nil {
		f.AgentDown = true
	} else {
		own := ns.OwnInterfaces()
		routed := map[string]bool{}
		for _, r := range st.DefaultRoutes {
			routed[r.Dev] = true
		}
		for _, i := range st.Interfaces {
			if i.Loopback || own[i.Name] || strings.Contains(i.Name, ".") {
				continue
			}
			c := Card{Name: i.Name, MAC: i.MAC, Up: i.State == "UP", HasRoute: routed[i.Name]}
			for _, a := range i.Addresses {
				if !strings.Contains(a, ":") {
					c.Addresses = append(c.Addresses, a)
				}
			}
			if r, ok := roles[i.Name]; ok && r.Role != network.RoleUnused {
				c.Role = r.Role
			}
			f.Cards = append(f.Cards, c)
		}
		sort.Slice(f.Cards, func(a, b int) bool { return f.Cards[a].Name < f.Cards[b].Name })
	}
	f.RolesApplied = len(ns.AppliedLANs()) > 0 && ns.HasWANAndLAN()
	f.ConfirmTimeout = ns.ConfirmTimeout()
	for _, r := range roles {
		switch r.Role {
		case netplangen.RoleWAN:
			f.WANName = r.Name
			f.WANMethod, f.WANCIDR, f.WANGateway, f.WANDNS, f.PPPoEUser = r.IPv4Method, r.IPv4CIDR, r.IPv4Gateway, r.IPv4DNS, r.PPPoEUsername
			if r.VLAN > 0 {
				f.VLAN = strconv.Itoa(r.VLAN)
			}
		case netplangen.RoleLAN:
			f.LANName, f.LANCIDR = r.Name, r.IPv4CIDR
		}
	}
	if f.RolesApplied && d.Paths != nil {
		f.Internet = internetState(d.Paths())
	}
	qs := qossvc.New()
	if q, err := qossvc.ReadSection(); err == nil {
		f.SpeedSet = q.Enabled && q.DownKbit > 0 && q.UpKbit > 0
	}
	f.MeasuredDown, f.MeasuredUp = qs.MeasuredMbit()
	vs := vpnsvc.New()
	vset := vs.Load()
	f.ChannelSet = vset.ActiveSlug != "" && vset.Mode == vpnsvc.ModeBlack
	profiles := vs.Profiles()
	f.Profiles = len(profiles)
	if len(profiles) > 0 {
		f.ProfileSlug, f.ProfileName = profiles[0].Slug, profiles[0].Name
	}
	if f.ChannelSet {
		if vst, err := vs.Status(); err == nil {
			f.ChannelUp = vst.Online
		}
	}
	if f.RolesApplied {
		if _, leases, err := dhcp.New().Leases(); err == nil {
			f.Leases = len(leases)
		}
	}
	return f
}

func internetState(paths []pathmon.Snapshot) string {
	for _, p := range paths {
		if p.Kind != pathmon.Direct {
			continue
		}
		switch p.State {
		case pathprobe.Up:
			return "up"
		case pathprobe.Down:
			return "down"
		}
	}
	return ""
}

func (f Facts) Wizard() wizard.Facts {
	w := wizard.Facts{Set: map[wizard.Fact]bool{}, Cards: len(f.Cards)}
	w.Set[wizard.FactAccount] = f.HasAdmin
	w.Set[wizard.FactRestore] = f.Skipped["restore"] || f.RolesApplied
	w.Set[wizard.FactWAN] = f.WANDraft != "" || f.RolesApplied
	w.Set[wizard.FactLAN] = f.LANDraft != "" || f.RolesApplied || (len(f.Cards) == 2 && f.WANDraft != "")
	w.Set[wizard.FactRoles] = f.RolesApplied
	w.Set[wizard.FactInternet] = f.Skipped["internet"] || f.Internet == "up"
	w.Set[wizard.FactSpeed] = f.Skipped["speed"] || f.SpeedSet
	w.Set[wizard.FactChannel] = f.Skipped["channel"] || f.ChannelSet
	w.Set[wizard.FactFinished] = f.Finished
	return w
}

func (f Facts) SuggestWAN() string {
	for _, c := range f.Cards {
		if c.HasRoute {
			return c.Name
		}
	}
	for _, c := range f.Cards {
		if len(c.Addresses) > 0 {
			return c.Name
		}
	}
	for _, c := range f.Cards {
		if c.Up {
			return c.Name
		}
	}
	return ""
}

func (f Facts) ChosenLAN() string {
	if f.LANDraft != "" {
		return f.LANDraft
	}
	if len(f.Cards) == 2 && f.WANDraft != "" {
		for _, c := range f.Cards {
			if c.Name != f.WANDraft {
				return c.Name
			}
		}
	}
	return ""
}

var lanCandidates = []string{"192.168.11.1/24", "192.168.21.1/24", "192.168.31.1/24", "10.11.0.1/24"}

func (f Facts) SuggestLANCIDR() string {
	var taken []netip.Prefix
	for _, c := range f.Cards {
		for _, a := range c.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				taken = append(taken, p.Masked())
			}
		}
	}
	for _, cand := range lanCandidates {
		p, err := netip.ParsePrefix(cand)
		if err != nil {
			continue
		}
		clash := false
		for _, t := range taken {
			if t.Overlaps(p.Masked()) {
				clash = true
				break
			}
		}
		if !clash {
			return cand
		}
	}
	return lanCandidates[0]
}

func (f Facts) Card(name string) (Card, bool) {
	for _, c := range f.Cards {
		if c.Name == name {
			return c, true
		}
	}
	return Card{}, false
}

func ChooseWAN(f Facts, name string) error {
	if _, ok := f.Card(name); !ok {
		return errUnknownCard
	}
	if err := settings.Set(SettingWANCard, name); err != nil {
		return err
	}
	if settings.Get(SettingLANCard) == name {
		return settings.Set(SettingLANCard, "")
	}
	return nil
}

func ChooseLAN(f Facts, name string) error {
	if _, ok := f.Card(name); !ok || name == f.WANDraft {
		return errUnknownCard
	}
	return settings.Set(SettingLANCard, name)
}

func Skip(key string) error {
	s := skipped()
	s[key] = true
	return settings.Set(SettingSkipped, join(s))
}

func Unskip(key string) error {
	s := skipped()
	delete(s, key)
	return settings.Set(SettingSkipped, join(s))
}

func Finish() error { return settings.Set(SettingFinished, "1") }

func Finished() bool { return settings.Get(SettingFinished) == "1" }

func ClearDrafts() {
	_ = settings.Set(SettingWANCard, "")
	_ = settings.Set(SettingLANCard, "")
}

func skipped() map[string]bool {
	out := map[string]bool{}
	for _, k := range strings.Split(settings.Get(SettingSkipped), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = true
		}
	}
	return out
}

func join(s map[string]bool) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

type textError string

func (e textError) Error() string { return string(e) }

var (
	errUnknownCard error = textError("такой карты у сервера нет — обновите страницу")

	ErrUnknownStep error = textError("такого шага в мастере нет — начните с начала")
)

func InSameNet(c Card, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, a := range c.Addresses {
		if _, n, err := net.ParseCIDR(a); err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
