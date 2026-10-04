package vpn

import (
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	dnssvc "github.com/vpn-vendor/vpn-panel-core/app/services/dns"
	netsvc "github.com/vpn-vendor/vpn-panel-core/app/services/network"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const (
	SettingActive    = "vpn.active_slug"
	SettingMode      = "vpn.mode"
	SettingOnFailure = "vpn.on_failure"
	SettingMTU       = "vpn.mtu"
	SettingDNSChoice = "vpn.dns_choice"

	settingProbeTarget = "vpn.probe_target."
)

const (
	ModeWhite = "white"
	ModeBlack = "black"

	FailStrict = "strict"
	FailDirect = "direct"

	DNSOurs   = "ours"
	DNSConfig = "config"
)

type Service struct {
	net *netsvc.Service
	dns *dnssvc.Service
	qos *qossvc.Service
}

func New() *Service {
	return &Service{net: netsvc.New(), dns: dnssvc.New(), qos: qossvc.New()}
}

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

type Settings struct {
	ActiveSlug string
	Mode       string
	OnFailure  string
	MTU        int
	DNSChoice  string
}

func (s *Service) Load() Settings {
	st := Settings{
		ActiveSlug: s.setting(SettingActive),
		Mode:       s.setting(SettingMode),
		OnFailure:  s.setting(SettingOnFailure),
		MTU:        atoiSafe(s.setting(SettingMTU)),
		DNSChoice:  s.setting(SettingDNSChoice),
	}
	return NormalizeSettings(st)
}

func NormalizeSettings(st Settings) Settings {
	if st.Mode != ModeBlack {
		st.Mode = ModeWhite
	}
	if st.OnFailure != FailDirect {
		st.OnFailure = FailStrict
	}
	if st.DNSChoice != DNSConfig {
		st.DNSChoice = DNSOurs
	}
	if st.MTU != 0 && (st.MTU < vpndriver.MinMTU || st.MTU > vpndriver.MaxMTU) {
		st.MTU = 0
	}
	return st
}

func (s *Service) Profiles() []models.VPNProfile {
	var rows []models.VPNProfile
	_ = facades.Orm().Query().OrderBy("id").Find(&rows)
	return rows
}

func (s *Service) Profile(slug string) (models.VPNProfile, bool) {
	var row models.VPNProfile
	if slug == "" {
		return row, false
	}
	if err := facades.Orm().Query().Where("slug", slug).First(&row); err != nil || row.ID == 0 {
		return row, false
	}
	return row, true
}

type ImportResult struct {
	Slug     string
	Warnings []string
}

func (s *Service) Import(name, config string) (*ImportResult, error) {
	d, err := vpnproto.Detect(config)
	if err != nil {
		return nil, err
	}
	slug := s.uniqueSlug(vpndriver.Slug(name))
	resp, err := s.client().Call("vpn.import", map[string]any{"slug": slug, "protocol": string(d.ID), "config": config})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Meta     vpndriver.Meta `json:"meta"`
		Warnings []string       `json:"warnings"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	prof := SectionProfile{
		Name: name, Slug: slug, Protocol: string(r.Meta.Protocol),
		Transport: r.Meta.Transport, EndpointHost: r.Meta.EndpointHost, EndpointPort: r.Meta.EndpointPort,
		PeerKey: r.Meta.PeerKey, Addresses: strings.Join(r.Meta.Addresses, ", "),
		AllowedIPs: strings.Join(r.Meta.AllowedIPs, ", "), ConfigDNS: strings.Join(r.Meta.ConfigDNS, ", "),
		ConfigMTU: r.Meta.ConfigMTU, Keepalive: r.Meta.Keepalive, FullTunnel: r.Meta.FullTunnel,
		VoiceFit: r.Meta.VoiceFit,
	}
	if _, err := Edit(func(v *Section) error { v.Profiles = append(v.Profiles, prof); return nil }); err != nil {

		if _, rerr := s.client().Call("vpn.remove", map[string]any{"slug": slug, "protocol": prof.Protocol}); rerr != nil {
			log.Printf("vpn: файл отвергнутого профиля %q не убран: %v", slug, rerr)
		}
		return nil, err
	}
	return &ImportResult{Slug: slug, Warnings: r.Warnings}, nil
}

func (s *Service) Remove(slug string) error {
	cur, err := ReadSection()
	if err != nil {
		return err
	}
	if cur.Mode == ModeBlack && cur.ActiveSlug == slug {
		var errs fielderr.List
		errs.Add("active_slug", "это подключение выбрано для защищённого режима — сначала переключите офис на прямой доступ в интернет, потом удаляйте")
		return &change.Rejected{Errors: errs}
	}
	remove := func(v *Section) error {
		v.Profiles = slices.DeleteFunc(v.Profiles, func(p SectionProfile) bool { return p.Slug == slug })
		if v.ActiveSlug == slug {
			v.ActiveSlug = ""
		}
		return nil
	}
	if err := change.Check(sectionFuncs(), remove); err != nil {
		return err
	}
	params := map[string]any{"slug": slug}
	if p, ok := s.Profile(slug); ok && p.Protocol != "" {
		params["protocol"] = p.Protocol
	}
	resp, err := s.client().Call("vpn.remove", params)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	_, err = Edit(remove)
	return err
}

func (s *Service) uniqueSlug(base string) string {
	return vpndriver.UniqueSlug(base, func(slug string) bool {
		_, exists := s.Profile(slug)
		return exists
	})
}

type Status struct {
	Mode string `json:"mode"`

	IntentBroken bool   `json:"intent_broken"`
	Slug         string `json:"slug"`
	OnFailure    string `json:"on_failure"`
	Present      bool   `json:"present"`
	Online       bool   `json:"online"`
	Degraded     bool   `json:"degraded"`
	RetryInSec   int64  `json:"retry_in_sec"`
	RetryPaused  bool   `json:"retry_paused"`

	SelfHealing bool `json:"self_healing"`

	DataDead          bool  `json:"data_dead"`
	DataSuspect       bool  `json:"data_suspect"`
	DataRestarts      int64 `json:"data_restarts"`
	DataRestartBudget int64 `json:"data_restart_budget"`

	Session struct {
		ID    int64 `json:"id"`
		Since int64 `json:"since"`
	} `json:"session"`
	MTU         int      `json:"mtu"`
	MTUWanted   int      `json:"mtu_wanted"`
	EndpointIP  string   `json:"endpoint_ip"`
	Endpoint    string   `json:"endpoint"`
	HandshakeS  int64    `json:"handshake_age_sec"`
	RxBytes     int64    `json:"rx_bytes"`
	TxBytes     int64    `json:"tx_bytes"`
	ProfileList []string `json:"profiles"`

	Cores int     `json:"cores"`
	Load1 float64 `json:"load1"`
	AESNI bool    `json:"aes_ni"`

	DataPlane vpndriver.Truth `json:"data_plane"`

	BlockedOutbound int64 `json:"blocked_outbound"`
	OutboundGuard   bool  `json:"outbound_guard"`

	Protocol        string   `json:"protocol"`
	Transport       string   `json:"transport"`
	KernelDataPlane bool     `json:"kernel_data_plane"`
	ServerPushed    []string `json:"server_pushed"`
	PeerIPv4        string   `json:"peer_ipv4"`

	ProcState    string `json:"proc_state"`
	FailReason   string `json:"fail_reason"`
	FailCount    int    `json:"fail_count"`
	LastFailUnix int64  `json:"last_fail_unix"`
}

func (s *Service) Status() (*Status, error) {
	resp, err := s.client().Call("vpn.status", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var st Status
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

type modeState struct {
	Firewall nftgen.FirewallPlan `json:"firewall"`
	DNS      unboundgen.Plan     `json:"dns"`
	QoS      any                 `json:"qos"`
}

func (s *Service) Apply(st Settings) (bool, error) {
	white, black, proto, err := s.buildModes(st)
	if err != nil {
		return false, err
	}
	resp, cerr := s.client().Call("vpn.apply", map[string]any{
		"plan": map[string]any{
			"slug":       st.ActiveSlug,
			"protocol":   string(proto),
			"mode":       st.Mode,
			"on_failure": st.OnFailure,
			"mtu":        st.MTU,
		},
		"white": white,
		"black": black,
	})
	if cerr != nil {
		return false, cerr
	}
	if resp.Error != nil {
		return false, resp.Error
	}
	var r struct {
		Changed bool `json:"changed"`
	}
	_ = json.Unmarshal(resp.Result, &r)
	return r.Changed, nil
}

type ErrNotReady struct{ Text string }

func (e *ErrNotReady) Error() string { return e.Text }

func (s *Service) buildModes(st Settings) (modeState, modeState, vpndriver.Protocol, error) {
	fw := s.net.BuildFirewall()
	if len(fw.WANs) == 0 || len(fw.LANs) == 0 {
		return modeState{}, modeState{}, "", &ErrNotReady{
			Text: "Сначала назначьте на странице «Сеть», какая карта смотрит в интернет, а какая — в офис."}
	}
	dnsPlan := s.dns.BuildPlan()
	qosPlan := s.qos.BuildPlan()

	profile, haveProfile := s.Profile(st.ActiveSlug)
	var proto vpndriver.Protocol
	if haveProfile {
		proto = vpnproto.Stored(profile.Protocol)
	}
	iface := vpnproto.Iface(proto)

	whiteQoS := qosPlan
	whiteQoS.Tunnel = ""
	white := modeState{Firewall: fw, DNS: dnsPlan, QoS: whiteQoS}

	blackFW := fw
	blackDNS := dnsPlan
	blackQoS := qosPlan
	blackQoS.Tunnel = iface
	if iface != "" {
		blackFW.Tunnel = &nftgen.FirewallTunnel{Iface: iface}
	}

	if st.Mode == ModeBlack {
		if !haveProfile {
			return modeState{}, modeState{}, "", &ErrNotReady{
				Text: "Сначала загрузите файл подключения и выберите его."}
		}

		passport, known := vpnproto.Passport(proto, profile.Transport)
		if !known {
			return modeState{}, modeState{}, "", &ErrNotReady{
				Text: "Протокол этого подключения эта версия панели не знает — загрузите файл подключения заново."}
		}
		if passport.AddressAtImport {
			blackDNS.OutgoingAddress = firstAddress(profile.Addresses)
			if blackDNS.OutgoingAddress == "" {
				return modeState{}, modeState{}, "", &ErrNotReady{
					Text: "В файле подключения нет адреса обычного вида — загрузите конфигурацию заново."}
			}
		}

		if st.DNSChoice == DNSConfig {
			if list := splitList(profile.ConfigDNS); len(list) > 0 {
				blackDNS.Forwarders = list
			}
		}
	}
	black := modeState{Firewall: blackFW, DNS: blackDNS, QoS: blackQoS}
	return white, black, proto, nil
}

type TimeSync struct {
	OffsetSec int64  `json:"offset_sec"`
	Server    string `json:"server"`
	Changed   bool   `json:"changed"`
}

func (s *Service) TimeSync() (*TimeSync, error) {
	resp, err := s.client().Call("system.timesync", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r TimeSync
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Service) QosPlan() qosgen.Plan { return s.qos.BuildPlan() }

type MTUProbe struct {
	Recommended int  `json:"recommended"`
	Blackhole   bool `json:"blackhole"`
	Outer       struct {
		Found   bool `json:"found"`
		PathMTU int  `json:"path_mtu"`
	} `json:"outer"`
	Inner struct {
		Found   bool `json:"found"`
		PathMTU int  `json:"path_mtu"`
	} `json:"inner"`
}

func (s *Service) MTUProbe() (*MTUProbe, error) {
	resp, err := s.client().Call("vpn.mtu_probe", map[string]any{
		"inner_target": unboundgen.Upstream[0],
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r MTUProbe
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func firstAddress(list string) string {
	for _, part := range splitList(list) {
		if i := strings.Index(part, "/"); i > 0 {
			part = part[:i]
		}
		if strings.Count(part, ".") == 3 {
			return part
		}
	}
	return ""
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) setting(key string) string { return settings.Get(key) }

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (s *Service) ProbeTarget(slug string) string {
	if slug == "" {
		return ""
	}
	return settings.Get(settingProbeTarget + slug)
}

func (s *Service) SetProbeTarget(slug, target string) error {
	_, err := Edit(func(v *Section) error {
		p, ok := profileOf(v, slug)
		if !ok {
			return errors.New("подключение не найдено")
		}
		p.ProbeTarget = target
		return nil
	})
	return err
}

func (s *Service) Audit(event, ip, details string) {
	securitylog.Record(models.AuthEvent{Event: event, IP: ip, Details: details, OccurredAt: time.Now()})
}
