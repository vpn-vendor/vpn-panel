package system

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const SettingSeen = "surroundings.seen"

func (s *Service) Surroundings() (hostcaps.Surroundings, error) {
	var st hostcaps.Surroundings
	resp, err := s.client().Call("host.surroundings", map[string]any{})
	if err != nil {
		return st, err
	}
	if resp.Error != nil {
		return st, resp.Error
	}
	err = json.Unmarshal(resp.Result, &st)
	return st, err
}

func (s *Service) Rescan(reset []string) error {
	params := map[string]any{}
	if len(reset) > 0 {
		params["reset"] = reset
	}
	resp, err := s.client().Call("host.rescan", params)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

var eventFamily = map[string][2]string{
	"surroundings.http_port":     {"http_port_found", "http_port_cleared"},
	"surroundings.tls_port":      {"tls_port_found", "tls_port_cleared"},
	"surroundings.dhcp_host":     {"foreign_dhcp_found", "foreign_dhcp_cleared"},
	"surroundings.forward_boot":  {"forward_boot_found", "forward_boot_cleared"},
	"surroundings.dhcp_lan":      {"lan_dhcp_found", "lan_dhcp_cleared"},
	"surroundings.forward_cut":   {"forward_cut_found", "forward_cut_cleared"},
	"surroundings.forward_off":   {"forward_off_found", "forward_off_cleared"},
	"surroundings.own_table":     {"own_table_found", "own_table_cleared"},
	"legacy.gateway":             {"legacy_found", "legacy_cleared"},
	"legacy.danger.sudo":         {"legacy_sudo_found", "legacy_sudo_cleared"},
	"legacy.danger.root_service": {"legacy_root_service_found", "legacy_root_service_cleared"},
	"legacy.danger.terminal":     {"legacy_terminal_found", "legacy_terminal_cleared"},
	"legacy.danger.usb":          {"legacy_usb_found", "legacy_usb_cleared"},
	"legacy.danger.keys":         {"legacy_keys_found", "legacy_keys_cleared"},
	"legacy.pppoe":               {"legacy_pppoe_found", "legacy_pppoe_cleared"},
	"legacy.tunnel":              {"legacy_tunnel_found", "legacy_tunnel_cleared"},
	"legacy.rerun":               {"legacy_rerun", ""},
}

type SurroundSync struct {
	read   func() (hostcaps.Surroundings, error)
	load   func() string
	save   func(string) error
	record func(code, details string)
	now    func() time.Time
}

func NewSurroundSync() *SurroundSync {
	return &SurroundSync{
		read: New().Surroundings,
		load: func() string { return settings.Get(SettingSeen) },
		save: func(v string) error { return settings.Set(SettingSeen, v) },
		record: func(code, details string) {
			securitylog.Record(models.AuthEvent{Event: code, Details: details, OccurredAt: time.Now()})
		},
		now: time.Now,
	}
}

type SeenFact struct {
	Answer string `json:"answer"`
	Level  string `json:"level,omitempty"`
	Cause  string `json:"cause,omitempty"`
	Title  string `json:"title,omitempty"`
	Found  string `json:"found,omitempty"`
	Value  string `json:"value,omitempty"`

	At string `json:"at,omitempty"`
}

func parseSeen(raw string) map[string]SeenFact {
	seen := map[string]SeenFact{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &seen)
	}
	return seen
}

func LastSeen() map[string]SeenFact { return parseSeen(settings.Get(SettingSeen)) }

func (y *SurroundSync) Step() error {
	st, err := y.read()
	if err != nil || st.Settling {
		return err
	}
	seen := parseSeen(y.load())
	changed := false
	for _, f := range st.Facts {
		codes, known := eventFamily[f.ID]
		if !known || f.Answer == hostcaps.Unknown {

			continue
		}
		was := seen[f.ID]
		next := SeenFact{Answer: string(f.Answer), Level: f.Level, Cause: f.Cause, Title: f.Title, Found: f.Found,
			Value: f.Value, At: was.At}
		if was.Answer != next.Answer || raised(f.ID, was) != raised(f.ID, next) {

			details := strings.TrimSpace(f.Title + " " + humanValue(f))
			switch {
			case raised(f.ID, next) && !raised(f.ID, was):
				y.record(codes[0], details)
			case raised(f.ID, was) && !raised(f.ID, next) && codes[1] != "":
				y.record(codes[1], details)
			}
			next.At = y.now().UTC().Format(time.RFC3339)
		}
		if next != was {
			seen[f.ID] = next
			changed = true
		}
	}
	if !changed {
		return nil
	}
	raw, _ := json.Marshal(seen)
	return y.save(string(raw))
}

func raised(id string, f SeenFact) bool {
	if f.Answer != string(hostcaps.Yes) {
		return false
	}
	return id != "surroundings.forward_cut" || f.Level == hostcaps.LevelError
}

func humanValue(f hostcaps.Fact) string {
	switch f.ID {
	case "legacy.gateway":
		return legacyvpn.ModeWord(f.Value)
	case "legacy.running":
		return ""
	}
	return f.Value
}

func (s *Service) DHCPCheck(lans, cards []string, consent *network.TakeoverConsent) (message, warning string, err error) {
	params := map[string]any{"lans": lans, "plan_cards": cards}
	if consent != nil && len(consent.IDs) > 0 {
		params["takeover"] = consent
	}
	resp, err := s.client().Call("dhcp.check", params)
	if err != nil {
		return "", "", err
	}
	if resp.Error != nil {
		return "", "", resp.Error
	}
	var r struct {
		Conflict bool   `json:"conflict"`
		Message  string `json:"message"`
		Warning  string `json:"warning"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return "", "", err
	}
	if !r.Conflict {
		return "", r.Warning, nil
	}
	return r.Message, r.Warning, nil
}
