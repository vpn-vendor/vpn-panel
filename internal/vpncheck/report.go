package vpncheck

import (
	"fmt"
	"time"
)

type Kind string

const (
	KindVoice Kind = "voice"

	KindEcho Kind = "echo"

	KindConnection Kind = "connection"

	KindSize Kind = "size"
)

const (
	MinVoiceSamples = 1000
	MinProbeSamples = 100
)

const MinSizeSamples = 10

func MinSamples(k Kind) int {
	switch k {
	case KindVoice:
		return MinVoiceSamples
	case KindSize:
		return MinSizeSamples
	}
	return MinProbeSamples
}

func SampleNote(k Kind, sent int) string {
	switch {
	case sent == 0:
		return "измерить не удалось"
	case sent < MinSamples(k):
		return fmt.Sprintf("по %d измерениям — мало для вывода, нужно не меньше %d", sent, MinSamples(k))
	default:
		return fmt.Sprintf("по %d измерениям", sent)
	}
}

func Trustworthy(k Kind, sent int) bool { return sent >= MinSamples(k) }

type Probe struct {
	Kind   Kind   `json:"kind"`
	Title  string `json:"title"`
	Target string `json:"target"`
	Stats  Stats  `json:"stats"`
	Note   string `json:"note"`
	Err    string `json:"err,omitempty"`
}

func (p Probe) OK() bool { return p.Err == "" && Trustworthy(p.Kind, p.Stats.Sent) }

type Speed struct {
	TunnelDownKbit   int       `json:"tunnel_down_kbit"`
	BaselineDownKbit int       `json:"baseline_down_kbit"`
	BaselineAt       time.Time `json:"baseline_at"`
	Sources          []string  `json:"sources"`
	Err              string    `json:"err,omitempty"`

	BaselineFresh  bool   `json:"baseline_fresh,omitempty"`
	BaselineSource string `json:"baseline_source,omitempty"`
	DirectErr      string `json:"direct_err,omitempty"`
}

type QueueDrops struct {
	Total  int64            `json:"total"`
	ByName map[string]int64 `json:"by_name"`
	Err    string           `json:"err,omitempty"`
}

type Report struct {
	StartedAt time.Time     `json:"started_at"`
	Took      time.Duration `json:"took"`
	Mode      string        `json:"mode"`

	UnderLoad bool `json:"under_load"`

	LoadBytes int64 `json:"load_bytes"`

	Service   Probe `json:"service"`
	Data      Probe `json:"data"`
	DirectLeg Probe `json:"direct_leg"`
	TunnelLeg Probe `json:"tunnel_leg"`
	Large     Probe `json:"large"`

	Speed *Speed     `json:"speed,omitempty"`
	Queue QueueDrops `json:"queue"`

	TariffDownKbit    int `json:"tariff_down_kbit"`
	TariffUpKbit      int `json:"tariff_up_kbit"`
	ShapedTunDownKbit int `json:"shaped_tun_down_kbit"`
	ShapedTunUpKbit   int `json:"shaped_tun_up_kbit"`

	Cores     int     `json:"cores"`
	LoadStart float64 `json:"load_start"`
	LoadEnd   float64 `json:"load_end"`

	Notes []string `json:"notes,omitempty"`
}

func (r *Report) LoadMB() int64 { return r.LoadBytes / 1000000 }

func (r *Report) LoadOK() bool { return r.UnderLoad && r.LoadBytes >= loadProofBytes }

const loadProofBytes = 50 * 1000 * 1000

func (r *Report) Probes() []Probe {
	return []Probe{r.DirectLeg, r.TunnelLeg, r.Service, r.Data, r.Large}
}

func (r *Report) Blackhole() bool {
	if r.Large.Err != "" || r.Large.Stats.Sent == 0 {
		return false
	}
	if r.Service.Err != "" || r.Service.Stats.Sent == 0 {
		return false
	}
	return r.Service.Stats.LossPct < 50 && r.Large.Stats.LossPct >= 80
}

func (r *Report) Facts() (loadPeak float64,
	serviceLoss, dataLoss, rttBase, rttTunnel float64, sample int,
	queueDropped int64, tunnelDown, directDown int) {

	loadPeak = r.LoadStart
	if r.LoadEnd > loadPeak {
		loadPeak = r.LoadEnd
	}
	if r.Service.Err == "" {
		serviceLoss = r.Service.Stats.LossPct
		sample = r.Service.Stats.Sent
	}
	if r.Data.Err == "" {
		dataLoss = r.Data.Stats.LossPct
		if r.Data.Stats.Sent > sample {
			sample = r.Data.Stats.Sent
		}
	}
	if r.DirectLeg.OK() {
		rttBase = r.DirectLeg.Stats.AvgMs
	}
	if r.TunnelLeg.OK() {
		rttTunnel = r.TunnelLeg.Stats.AvgMs
	}
	if r.Queue.Err == "" {
		queueDropped = r.Queue.Total
	}
	if r.Speed != nil && r.Speed.Err == "" {
		tunnelDown = r.Speed.TunnelDownKbit
		directDown = r.Speed.BaselineDownKbit
	}
	return
}
