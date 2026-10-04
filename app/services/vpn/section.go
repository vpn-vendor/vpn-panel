package vpn

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/usertext"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const MaxProfileName = 60

type Section struct {
	ActiveSlug string           `json:"active_slug" setting:"vpn.active_slug"`
	Mode       string           `json:"mode" setting:"vpn.mode"`
	OnFailure  string           `json:"on_failure" setting:"vpn.on_failure"`
	MTU        int              `json:"mtu" setting:"vpn.mtu"`
	DNSChoice  string           `json:"dns_choice" setting:"vpn.dns_choice"`
	Profiles   []SectionProfile `json:"profiles" table:"vpn_profiles"`
}

type SectionProfile struct {
	Name         string `json:"name"`
	Slug         string `json:"slug" owner:"id"`
	Protocol     string `json:"protocol"`
	Transport    string `json:"transport"`
	EndpointHost string `json:"endpoint_host"`
	EndpointPort int    `json:"endpoint_port"`
	PeerKey      string `json:"peer_key"`
	Addresses    string `json:"addresses"`
	AllowedIPs   string `json:"allowed_ips"`
	ConfigDNS    string `json:"config_dns"`
	ConfigMTU    int    `json:"config_mtu"`
	Keepalive    int    `json:"keepalive"`
	FullTunnel   bool   `json:"full_tunnel"`
	VoiceFit     bool   `json:"voice_fit"`
	ProbeTarget  string `json:"probe_target" setting:"vpn.probe_target."`
}

func ReadSection() (Section, error) {
	st := New().Load()
	targets, err := settings.Prefixed(settingProbeTarget)
	if err != nil {
		return Section{}, err
	}
	var rows []models.VPNProfile
	if err := facades.Orm().Query().OrderBy("id").Find(&rows); err != nil {
		return Section{}, err
	}
	out := Section{ActiveSlug: st.ActiveSlug, Mode: st.Mode, OnFailure: st.OnFailure, MTU: st.MTU,
		DNSChoice: st.DNSChoice, Profiles: []SectionProfile{}}
	for _, r := range rows {
		out.Profiles = append(out.Profiles, SectionProfile{
			Name: r.Name, Slug: r.Slug, Protocol: string(vpnproto.Stored(r.Protocol)), Transport: r.Transport,
			EndpointHost: r.EndpointHost, EndpointPort: r.EndpointPort, PeerKey: r.PeerKey,
			Addresses: r.Addresses, AllowedIPs: r.AllowedIPs, ConfigDNS: r.ConfigDNS, ConfigMTU: r.ConfigMTU,
			Keepalive: r.Keepalive, FullTunnel: r.FullTunnel, VoiceFit: r.VoiceFit,
			ProbeTarget: targets[r.Slug],
		})
	}
	return out, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	if v.Mode != ModeWhite && v.Mode != ModeBlack {
		errs.Add("mode", "режим — white или black")
	}
	if v.OnFailure != FailStrict && v.OnFailure != FailDirect {
		errs.Add("on_failure", "при падении канала — strict или direct")
	}
	if v.DNSChoice != DNSOurs && v.DNSChoice != DNSConfig {
		errs.Add("dns_choice", "серверы имён — ours или config")
	}
	if !mtuOK(v.MTU) {
		errs.Add("mtu", "размер пакета — 0 (подбирает панель) или от %d до %d", vpndriver.MinMTU, vpndriver.MaxMTU)
	}
	slugs := map[string]bool{}
	for n, p := range v.Profiles {
		key := ""
		if vpndriver.ValidSlug(p.Slug) {
			key = p.Slug
		}
		path := fielderr.Row("profiles", n, key)
		if slugs[p.Slug] {
			errs.Add(fielderr.Join(path, "slug"), "имя профиля %q повторяется", p.Slug)
		}
		slugs[p.Slug] = true
		errs.Under(path, validateProfile(p))
	}
	switch {
	case v.ActiveSlug != "" && !slugs[v.ActiveSlug]:
		errs.Add("active_slug", "выбранного подключения %q нет среди подключений", v.ActiveSlug)
	case v.ActiveSlug == "" && v.Mode == ModeBlack:
		errs.Add("active_slug", "выберите подключение — без него весь офис через защищённый канал направить не получится")
	}
	return errs
}

func validateProfile(p SectionProfile) fielderr.List {
	var errs fielderr.List
	if err := usertext.ValidatePlain(p.Name, MaxProfileName); err != nil {
		errs.Add("name", "%s", err.Error())
	}
	if !vpndriver.ValidSlug(p.Slug) {
		errs.Add("slug", "имя файла профиля составлено неверно")
	}
	d, ok := vpnproto.Lookup(vpndriver.Protocol(p.Protocol))
	if !ok {
		errs.Add("protocol", "протокол — %s", vpnproto.IDs())
		return errs
	}
	switch {
	case p.Transport != vpndriver.TransportUDP && p.Transport != vpndriver.TransportTCP:
		errs.Add("transport", "транспорт — udp или tcp")
	case !slices.Contains(d.Transports, p.Transport):
		errs.Add("transport", "%s работает только поверх %s", d.Label, strings.Join(d.Transports, " или "))
	}
	if !vpndriver.ValidHost(p.EndpointHost) {
		errs.Add("endpoint_host", "адрес сервера — IP или имя по правилам DNS")
	}

	if p.EndpointPort < 0 || p.EndpointPort > 65535 {
		errs.Add("endpoint_port", "порт сервера — от 1 до 65535 или не записан")
	}

	errs = append(errs, d.CheckMeta(vpndriver.Meta{Transport: p.Transport, PeerKey: p.PeerKey,
		Addresses: rawItems(p.Addresses), AllowedIPs: rawItems(p.AllowedIPs)})...)
	if !addrList(p.ConfigDNS) {
		errs.Add("config_dns", "серверы имён из файла — список адресов через запятую")
	}
	if !mtuOK(p.ConfigMTU) {
		errs.Add("config_mtu", "размер пакета из файла — 0 или от %d до %d", vpndriver.MinMTU, vpndriver.MaxMTU)
	}
	if p.Keepalive < 0 || p.Keepalive > 65535 {
		errs.Add("keepalive", "интервал проверки связи — от 0 до 65535 секунд")
	}
	if t, err := pathmon.ValidateTarget(p.ProbeTarget); err != nil {
		errs.Add("probe_target", "%s", err.Error())
	} else if t != p.ProbeTarget {
		errs.Add("probe_target", "цель пробы записана не в обычном виде адреса: %q", p.ProbeTarget)
	}
	return errs
}

func mtuOK(n int) bool { return n == 0 || (n >= vpndriver.MinMTU && n <= vpndriver.MaxMTU) }

func items(s string) ([]string, bool) {
	if s == "" {
		return nil, true
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		if parts[i] = strings.TrimSpace(p); parts[i] == "" {
			return nil, false
		}
	}
	return parts, true
}

func rawItems(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func addrList(s string) bool {
	parts, ok := items(s)
	if !ok {
		return false
	}
	for _, p := range parts {
		if _, err := netip.ParseAddr(p); err != nil {
			return false
		}
	}
	return true
}

func ApplySection(cur, want Section) error {
	added, changed, removed := change.Rows(cur.Profiles, want.Profiles, func(p SectionProfile) string { return p.Slug })
	return facades.Orm().Transaction(func(tx orm.Query) error {
		if err := settings.WriteChangedIn(tx, cur, want); err != nil {
			return err
		}
		for _, p := range removed {
			if _, err := tx.Where("slug", p.Slug).Delete(&models.VPNProfile{}); err != nil {
				return err
			}
			if err := settings.ForgetOwned(tx, settings.OwnerVPNProfile, p.Slug); err != nil {
				return err
			}
		}
		for _, p := range added {

			if err := settings.DropOwned(tx, settings.OwnerVPNProfile, p.Slug); err != nil {
				return err
			}
			row := profileRow(p)
			if err := tx.Create(&row); err != nil {
				return err
			}
		}
		for _, p := range changed {
			row := profileRow(p)
			if _, err := tx.Model(&models.VPNProfile{}).Where("slug", p.Slug).Update(map[string]any{
				"name": row.Name, "protocol": row.Protocol, "transport": row.Transport,
				"endpoint_host": row.EndpointHost, "endpoint_port": row.EndpointPort, "peer_key": row.PeerKey,
				"addresses": row.Addresses, "allowed_ips": row.AllowedIPs, "config_dns": row.ConfigDNS,
				"config_mtu": row.ConfigMTU, "keepalive": row.Keepalive, "full_tunnel": row.FullTunnel,
				"voice_fit": row.VoiceFit}); err != nil {
				return err
			}
		}
		for _, p := range append(added, changed...) {
			key := settingProbeTarget + p.Slug
			if p.ProbeTarget == "" {
				if err := settings.DeleteIn(tx, key); err != nil {
					return err
				}
			} else if err := settings.SetIn(tx, key, p.ProbeTarget); err != nil {
				return err
			}
		}
		return nil
	})
}

func profileRow(p SectionProfile) models.VPNProfile {
	return models.VPNProfile{Name: p.Name, Slug: p.Slug, Protocol: p.Protocol, Transport: p.Transport,
		EndpointHost: p.EndpointHost, EndpointPort: p.EndpointPort, PeerKey: p.PeerKey, Addresses: p.Addresses,
		AllowedIPs: p.AllowedIPs, ConfigDNS: p.ConfigDNS, ConfigMTU: p.ConfigMTU, Keepalive: p.Keepalive,
		FullTunnel: p.FullTunnel, VoiceFit: p.VoiceFit}
}

func sectionFuncs() change.Section[Section] {
	return change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}
}

func Edit(edit func(*Section) error) (Section, error) { return change.Apply(sectionFuncs(), edit) }

func profileOf(v *Section, slug string) (*SectionProfile, bool) {
	for i := range v.Profiles {
		if v.Profiles[i].Slug == slug {
			return &v.Profiles[i], true
		}
	}
	return nil, false
}
