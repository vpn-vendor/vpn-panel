package qosgen

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	IFBDevice       = "ifb-vpn0"
	IFBTunnelDevice = "ifb-vpn1"
)

const ShapePercent = 95

const TunnelShapePercent = 90

const TunnelOverhead = 60

const (
	MinKbit = 1_000
	MaxKbit = 10_000_000
)

type Plan struct {
	Enabled  bool   `json:"enabled"`
	WAN      string `json:"wan"`
	Tunnel   string `json:"tunnel,omitempty"`
	DownKbit int    `json:"down_kbit"`
	UpKbit   int    `json:"up_kbit"`
}

var ifnameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{1,14}$`)

func (p *Plan) Validate(knownNames map[string]bool) error {
	if !p.Enabled {
		return nil
	}
	if !ifnameRe.MatchString(p.WAN) {
		return fmt.Errorf("недопустимое имя интерфейса %q", p.WAN)
	}
	if knownNames != nil && !knownNames[p.WAN] {
		return fmt.Errorf("интерфейс %q не существует в системе", p.WAN)
	}

	if p.Tunnel != "" && !ifnameRe.MatchString(p.Tunnel) {
		return fmt.Errorf("недопустимое имя защищённого канала %q", p.Tunnel)
	}
	for _, v := range []struct {
		name string
		kbit int
	}{{"скачивание", p.DownKbit}, {"отдача", p.UpKbit}} {
		if v.kbit < MinKbit {
			return fmt.Errorf("скорость тарифа (%s) меньше 1 Мбит/с — офис останется без канала", v.name)
		}
		if v.kbit > MaxKbit {
			return fmt.Errorf("скорость тарифа (%s) больше 10 Гбит/с — проверьте значение", v.name)
		}
	}
	return nil
}

func (p *Plan) ShapedDownKbit() int { return p.DownKbit * ShapePercent / 100 }
func (p *Plan) ShapedUpKbit() int   { return p.UpKbit * ShapePercent / 100 }

func (p *Plan) TunnelDownKbit() int { return p.DownKbit * TunnelShapePercent / 100 }
func (p *Plan) TunnelUpKbit() int   { return p.UpKbit * TunnelShapePercent / 100 }

func (p *Plan) Commands() [][]string {
	up := strconv.Itoa(p.ShapedUpKbit()) + "kbit"
	down := strconv.Itoa(p.ShapedDownKbit()) + "kbit"
	cmds := [][]string{
		{"qdisc", "replace", "dev", p.WAN, "root", "cake", "bandwidth", up, "ethernet"},
		{"qdisc", "replace", "dev", p.WAN, "handle", "ffff:", "ingress"},
		{"filter", "replace", "dev", p.WAN, "parent", "ffff:", "matchall",
			"action", "mirred", "egress", "redirect", "dev", IFBDevice},
		{"qdisc", "replace", "dev", IFBDevice, "root", "cake", "bandwidth", down,
			"ethernet", "besteffort", "wash", "ingress"},
	}
	return append(cmds, p.TunnelCommands()...)
}

func (p *Plan) TunnelCommands() [][]string {
	if p.Tunnel == "" {
		return nil
	}
	overhead := strconv.Itoa(TunnelOverhead)
	up := strconv.Itoa(p.TunnelUpKbit()) + "kbit"
	down := strconv.Itoa(p.TunnelDownKbit()) + "kbit"
	return [][]string{
		{"qdisc", "replace", "dev", p.Tunnel, "root", "cake", "bandwidth", up, "overhead", overhead},
		{"qdisc", "replace", "dev", p.Tunnel, "handle", "ffff:", "ingress"},
		{"filter", "replace", "dev", p.Tunnel, "parent", "ffff:", "matchall",
			"action", "mirred", "egress", "redirect", "dev", IFBTunnelDevice},
		{"qdisc", "replace", "dev", IFBTunnelDevice, "root", "cake", "bandwidth", down,
			"overhead", overhead, "besteffort", "wash", "ingress"},
	}
}

func (p *Plan) TeardownCommands() [][]string {
	return [][]string{
		{"qdisc", "del", "dev", p.WAN, "root"},
		{"qdisc", "del", "dev", p.WAN, "ingress"},
	}
}

func CakeBandwidthBytes(kbit int) int64 { return int64(kbit) * 1000 / 8 }

type tcQdisc struct {
	Kind    string `json:"kind"`
	Root    bool   `json:"root"`
	Options struct {
		Bandwidth int64 `json:"bandwidth"`
	} `json:"options"`
}

func ActiveCake(tcJSON []byte) (bandwidthBytes int64, found bool, err error) {
	var list []tcQdisc
	if err := json.Unmarshal(tcJSON, &list); err != nil {
		return 0, false, fmt.Errorf("разбор вывода tc: %w", err)
	}
	for _, q := range list {
		if q.Kind == "cake" && q.Root {
			return q.Options.Bandwidth, true, nil
		}
	}
	return 0, false, nil
}

func HasIngress(tcJSON []byte) bool {
	var list []tcQdisc
	if json.Unmarshal(tcJSON, &list) != nil {
		return false
	}
	for _, q := range list {
		if q.Kind == "ingress" {
			return true
		}
	}
	return false
}

func ParseLinkSpeedMbit(content string) int {
	v, err := strconv.Atoi(strings.TrimSpace(content))
	if err != nil || v <= 0 {
		return -1
	}
	return v
}

func ParseLoad1(content string) string {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func ParseDropped(out []byte) int64 {
	var total int64
	for _, line := range strings.Split(string(out), "\n") {
		i := strings.Index(line, "dropped ")
		if i < 0 {
			continue
		}
		rest := line[i+len("dropped "):]
		end := strings.IndexAny(rest, ", )")
		if end < 0 {
			end = len(rest)
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(rest[:end]), 10, 64); err == nil {
			total += n
		}
	}
	return total
}
