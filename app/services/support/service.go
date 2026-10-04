package support

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const dir = "/run/vpn-panel"

const prefix = "vpn-panel-support-"

const requestShare = 2

type Name struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

type State struct {
	State string `json:"state"`
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	Lines int    `json:"lines"`
	At    int64  `json:"at"`
}

func (s State) Running() bool { return s.State == "running" }
func (s State) Ready() bool   { return s.State == "done" && s.Path != "" }
func (s State) Failed() bool  { return s.State == "failed" }

type Service struct {
	Template func() ([]byte, error)
}

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func names() []Name {
	var devices []models.Device
	_ = facades.Orm().Query().Find(&devices)
	var out []Name
	for _, d := range devices {
		for _, n := range []string{d.Label, d.PublicLabel, d.ProposedLabel, d.Hostname, d.Owner, d.Location, d.ProposedOwner, d.ProposedLocation} {
			if strings.TrimSpace(n) != "" {
				out = append(out, Name{Name: n, MAC: d.MAC})
			}
		}
	}
	var trusted []models.TrustedDevice
	_ = facades.Orm().Query().Find(&trusted)
	for _, t := range trusted {
		if strings.TrimSpace(t.Label) != "" {
			out = append(out, Name{Name: t.Label})
		}
	}
	return out
}

func events(budget int) []string {
	var rows []models.AuthEvent
	_ = facades.Orm().Query().OrderByDesc("occurred_at").Limit(lineLimit).Find(&rows)
	var out []string
	for _, r := range rows {
		title := r.Event
		if e, ok := securitylog.Lookup(r.Event); ok {
			title = e.Title
		}
		line := r.OccurredAt.UTC().Format(time.RFC3339) + " " + r.Event + " «" + title + "» " + r.IP + " " + r.Details
		if budget -= len(line) + 8; budget < 0 {
			out = append(out, "… журнал обрезан: не поместился в запрос")
			break
		}
		out = append(out, line)
	}
	return out
}

const lineLimit = 20000

func (s *Service) settings() []string {
	if s.Template == nil {
		return []string{"настройки не приложены"}
	}
	data, err := s.Template()
	if err != nil {
		return []string{"настройки не собрались"}
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") != nil {
		return []string{"настройки не разобраны"}
	}
	return strings.Split(pretty.String(), "\n")
}

func (s *Service) Collect() error {
	settings := s.settings()
	budget := agentrpc.MaxMessageSize / requestShare
	for _, l := range settings {
		budget -= len(l) + 8
	}
	params := map[string]any{
		"names": names(),
		"parts": map[string][]string{"panel-settings": settings, "panel-events": events(budget)},
	}
	resp, err := s.client().Call("support.collect", params)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

func (s *Service) State() (State, error) {
	var st State
	resp, err := s.client().Call("support.status", map[string]any{})
	if err != nil {
		return st, err
	}
	if resp.Error != nil {
		return st, resp.Error
	}
	return st, json.Unmarshal(resp.Result, &st)
}

func (s *Service) File() (string, []byte, error) {
	st, err := s.State()
	if err != nil {
		return "", nil, err
	}

	if !st.Ready() || filepath.Dir(st.Path) != dir || !strings.HasPrefix(filepath.Base(st.Path), prefix) {
		return "", nil, errors.New("файл сведений не готов")
	}
	data, err := os.ReadFile(st.Path) //nolint:gosec
	return filepath.Base(st.Path), data, err
}

type Decoded struct {
	Alias string
	Label string
}

func (s *Service) Decode() ([]Decoded, error) {
	var devices []models.Device
	if err := facades.Orm().Query().OrderBy("label").Find(&devices); err != nil {
		return nil, err
	}
	macs := make([]string, 0, len(devices))
	for _, d := range devices {
		macs = append(macs, d.MAC)
	}
	resp, err := s.client().Call("support.names", map[string]any{"macs": macs})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r struct {
		Names map[string]string `json:"names"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	out := make([]Decoded, 0, len(devices))
	for _, d := range devices {
		label := d.Label
		if label == "" {
			label = d.Hostname
		}
		if label == "" {
			label = d.MAC
		}
		out = append(out, Decoded{Alias: r.Names[d.MAC], Label: label})
	}
	return out, nil
}
