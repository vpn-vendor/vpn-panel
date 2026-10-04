package qos

import (
	"encoding/json"
	"log"
	"strconv"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
)

const (
	SettingEnabled  = "qos.enabled"
	SettingDownKbit = "qos.down_kbit"
	SettingUpKbit   = "qos.up_kbit"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) BuildPlan() qosgen.Plan {
	plan := qosgen.Plan{
		Enabled:  s.setting(SettingEnabled) == "1",
		DownKbit: atoiSafe(s.setting(SettingDownKbit)),
		UpKbit:   atoiSafe(s.setting(SettingUpKbit)),
	}
	var row models.Interface
	if err := facades.Orm().Query().Where("role", "wan").First(&row); err == nil {
		plan.WAN = netplangen.EffectiveWAN(netplangen.LinkIface(row.Name, row.VLAN), row.IPv4Method)
	}

	if iface := s.liveTunnel(); iface != "" {
		plan.Tunnel = iface
	}
	return plan
}

func (s *Service) liveTunnel() string {
	resp, err := s.client().Call("vpn.status", map[string]any{})
	if err != nil || resp == nil || resp.Error != nil {
		return ""
	}
	var st struct {
		Mode    string `json:"mode"`
		Present bool   `json:"present"`
		Iface   string `json:"iface"`
	}
	if json.Unmarshal(resp.Result, &st) != nil {
		return ""
	}
	if st.Mode == "black" && st.Present {
		return st.Iface
	}
	return ""
}

type Result struct {
	Changed  bool
	DownKbit int
	UpKbit   int
}

func (s *Service) Apply(plan qosgen.Plan) (*Result, error) {
	resp, err := s.client().Call("qos.apply", map[string]any{"plan": plan})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Changed  bool `json:"changed"`
		DownKbit int  `json:"down_kbit"`
		UpKbit   int  `json:"up_kbit"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return &Result{Changed: r.Changed, DownKbit: r.DownKbit, UpKbit: r.UpKbit}, nil
}

type Status struct {
	Enabled  bool   `json:"enabled"`
	Active   bool   `json:"active"`
	WAN      string `json:"wan"`
	DownKbit int    `json:"down_kbit"`
	UpKbit   int    `json:"up_kbit"`
	Cores    int    `json:"cores"`
	Load1    string `json:"load1"`
	LinkMbit int    `json:"link_mbit"`
}

func (s *Service) Status() (*Status, error) {
	resp, err := s.client().Call("qos.status", map[string]any{})
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

func (s *Service) setting(key string) string { return settings.Get(key) }

func (s *Service) setSetting(key, value string) {
	if err := settings.Set(key, value); err != nil {
		log.Printf("qos: %v", err)
	}
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
