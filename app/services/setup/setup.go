package setup

import (
	"encoding/json"
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
	"github.com/vpn-vendor/vpn-panel-core/app/services/system"
	vpnsvc "github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

const (
	SettingWANCard  = "setup.wan_card"
	SettingLANCard  = "setup.lan_card"
	SettingSkipped  = "setup.skipped"
	SettingFinished = "setup.finished"

	SettingTakeover = "setup.takeover"
)

type TakeoverFacts struct {
	Items  []system.TakeoverItem
	Digest string
	State  string
	Failed int

	Consent *network.TakeoverConsent
}

func (t TakeoverFacts) Approved() bool {
	return t.Consent != nil && t.Digest != "" && t.Consent.Digest == t.Digest
}

type Card struct {
	Name      string
	MAC       string
	Up        bool
	Addresses []string
	HasRoute  bool
	Role      string

	DHCPServer string
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

	WANCloneMAC string

	MeasuredDown, MeasuredUp int

	ConfirmTimeout int

	Internet string

	OfficeCut *hostcaps.Fact

	OfficeOK bool

	OfficeWhy   string
	SpeedSet    bool
	ChannelSet  bool
	ChannelUp   bool
	Profiles    int
	ProfileSlug string
	ProfileName string
	Leases      int
	Skipped     map[string]bool
	Finished    bool

	Takeover TakeoverFacts

	Legacy *legacyvpn.Settings
}

type Deps struct {
	Paths func() []pathmon.Snapshot

	Surroundings func() (hostcaps.Surroundings, error)

	Takeover func(lans, cards []string) (system.TakeoverPlan, error)

	TakeoverState func() (system.TakeoverPlan, error)

	Legacy func() (system.LegacySettings, error)
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
			c := Card{Name: i.Name, MAC: i.MAC, Up: i.State == "UP", HasRoute: routed[i.Name], DHCPServer: i.DHCPServer}
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
			f.WANCloneMAC = r.CloneMAC
		case netplangen.RoleLAN:
			f.LANName, f.LANCIDR = r.Name, r.IPv4CIDR
		}
	}
	if f.RolesApplied && d.Paths != nil {
		f.Internet = internetState(d.Paths())
	}

	if d.Legacy != nil {
		if l, err := d.Legacy(); err == nil && l.Found {
			s := l.Settings
			f.Legacy = &s
		}
	}

	f.Takeover.Consent = TakeoverConsent()
	switch {
	case !f.RolesApplied && d.Takeover != nil:
		if lan := f.ChosenLAN(); f.WANDraft != "" && lan != "" {
			if p, err := d.Takeover([]string{lan}, []string{f.WANDraft, lan}); err == nil {
				f.Takeover.Items, f.Takeover.Digest, f.Takeover.State, f.Takeover.Failed = p.Items, p.Digest, p.State, p.Failed
			}
		}
	case f.RolesApplied && d.TakeoverState != nil:
		if p, err := d.TakeoverState(); err == nil {
			f.Takeover.State, f.Takeover.Failed = p.State, p.Failed
		}
	}

	if f.RolesApplied && d.Surroundings != nil {
		if st, err := d.Surroundings(); err == nil {
			f.OfficeCut, f.OfficeOK, f.OfficeWhy = officePath(st)
		}
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

func officePath(st hostcaps.Surroundings) (cut *hostcaps.Fact, ok bool, why string) {
	if st.Settling {
		return nil, false, ""
	}

	for _, id := range []string{"surroundings.forward_cut", "surroundings.forward_off", "surroundings.own_table"} {
		if f, found := st.Fact(id); found && f.Answer == hostcaps.Yes && f.Level == hostcaps.LevelError {
			return &f, false, ""
		}
	}
	f, found := st.Fact("surroundings.forward_cut")
	switch {
	case !found:
		return nil, false, ""
	case f.Answer == hostcaps.Unknown:
		return nil, false, f.Found
	}

	return nil, f.How == hostcaps.HowCounter && (f.Answer == hostcaps.No || f.Answer == hostcaps.Yes), ""
}

func (f Facts) Wizard() wizard.Facts {
	w := wizard.Facts{Set: map[wizard.Fact]bool{}, Cards: len(f.Cards), Takeover: len(f.Takeover.Items)}
	w.Set[wizard.FactAccount] = f.HasAdmin
	w.Set[wizard.FactTakeover] = f.RolesApplied || f.Takeover.Approved()
	w.Set[wizard.FactRestore] = f.Skipped["restore"] || f.RolesApplied
	w.Set[wizard.FactWAN] = f.WANDraft != "" || f.RolesApplied
	w.Set[wizard.FactLAN] = f.LANDraft != "" || f.RolesApplied || (len(f.Cards) == 2 && f.WANDraft != "")
	w.Set[wizard.FactRoles] = f.RolesApplied
	w.Set[wizard.FactInternet] = f.Skipped["internet"] || (f.Internet == "up" && f.OfficeCut == nil)
	w.Set[wizard.FactSpeed] = f.Skipped["speed"] || f.SpeedSet
	w.Set[wizard.FactChannel] = f.Skipped["channel"] || f.ChannelSet
	w.Set[wizard.FactFinished] = f.Finished
	return w
}

func (f Facts) legacyCard(name string) string {
	if f.Legacy == nil || name == "" {
		return ""
	}
	if _, ok := f.Card(name); ok {
		return name
	}
	return ""
}

func (f Facts) SuggestWAN() string {
	if f.Legacy != nil {
		if c := f.legacyCard(f.Legacy.WAN.Card); c != "" {
			return c
		}
	}
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
	if f.Legacy != nil {
		if c := f.legacyCard(f.Legacy.LAN.Card); c != "" && c != f.WANDraft {
			return c
		}
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

		if f.Legacy != nil && c.Name == f.Legacy.LAN.Card {
			continue
		}
		for _, a := range c.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				taken = append(taken, p.Masked())
			}
		}
	}
	if f.Legacy != nil && f.Legacy.LAN.CIDR != "" {
		if p, err := netip.ParsePrefix(f.Legacy.LAN.CIDR); err == nil && !overlaps(taken, p.Masked()) {
			return f.Legacy.LAN.CIDR
		}
	}
	for _, cand := range lanCandidates {
		if p, err := netip.ParsePrefix(cand); err == nil && !overlaps(taken, p.Masked()) {
			return cand
		}
	}
	return lanCandidates[0]
}

func overlaps(taken []netip.Prefix, p netip.Prefix) bool {
	for _, t := range taken {
		if t.Overlaps(p) {
			return true
		}
	}
	return false
}

func (f Facts) LegacyReport() (taken, missing []string) {
	l := f.Legacy
	if l == nil {
		return nil, nil
	}
	switch l.WAN.Method {
	case legacyvpn.MethodDHCP:
		taken = append(taken, "карта в интернет "+l.WAN.Card+", адрес от провайдера автоматически")
	case legacyvpn.MethodStatic:
		taken = append(taken, "карта в интернет "+l.WAN.Card+", постоянный адрес "+l.WAN.CIDR+", шлюз "+l.WAN.Gateway)
	case legacyvpn.MethodPPPoE:
		t := "карта в интернет " + l.WAN.Card + ", PPPoE с логином " + l.WAN.PPPoEUser
		if l.WAN.PPPoEPassword {
			t += " и паролем"
		}
		taken = append(taken, t)
	}
	if l.LAN.Card != "" {
		taken = append(taken, "карта в офис "+l.LAN.Card+", адрес шлюза "+l.LAN.CIDR)
	}
	if l.DHCP.Subnet != "" {
		taken = append(taken, "адреса офису — в подсети "+l.DHCP.Subnet+" (диапазон панель задаёт сама)")
	}
	if l.VPN != nil {
		t := "подключение VPN " + legacyvpn.ProtocolWord(l.VPN.Protocol)
		if l.VPN.Endpoint != "" {
			t += " к серверу " + l.VPN.Endpoint
		}
		taken = append(taken, t+" — на шаге «Канал VPN»")
	}
	for _, m := range l.Missing {
		missing = append(missing, m.What+": "+m.Why)
	}
	return taken, missing
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

func ApproveTakeover(digest string, ids []string) error {
	if digest == "" {
		return errStaleTakeover
	}
	data, err := json.Marshal(network.TakeoverConsent{Digest: digest, IDs: ids})
	if err != nil {
		return err
	}
	return settings.Set(SettingTakeover, string(data))
}

func TakeoverConsent() *network.TakeoverConsent {
	raw := settings.Get(SettingTakeover)
	if raw == "" {
		return nil
	}
	var c network.TakeoverConsent
	if err := json.Unmarshal([]byte(raw), &c); err != nil || c.Digest == "" {
		return nil
	}
	return &c
}

func Finish() error { return settings.Set(SettingFinished, "1") }

func Finished() bool { return settings.Get(SettingFinished) == "1" }

func ClearDrafts() {
	_ = settings.Set(SettingWANCard, "")
	_ = settings.Set(SettingLANCard, "")
	_ = settings.Set(SettingTakeover, "")
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

	ErrUnknownStep   error = textError("такого шага в мастере нет — начните с начала")
	errStaleTakeover error = textError("список того, что выключит панель, устарел — проверьте его ещё раз")
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
