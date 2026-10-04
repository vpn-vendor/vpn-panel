package diagfacts

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Neighbour struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Dev   string `json:"dev"`
	State string `json:"state"`
}

type SetEntry struct {
	IP      string `json:"ip"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Expires int64  `json:"expires"`
}

type LinkStats struct {
	Name       string `json:"name"`
	SpeedMbit  int    `json:"speed_mbit"`
	Duplex     string `json:"duplex"`
	RxPackets  int64  `json:"rx_packets"`
	RxErrors   int64  `json:"rx_errors"`
	RxDropped  int64  `json:"rx_dropped"`
	RxCRC      int64  `json:"rx_crc_errors"`
	TxPackets  int64  `json:"tx_packets"`
	TxErrors   int64  `json:"tx_errors"`
	Collisions int64  `json:"collisions"`
}

type ProbeResult struct {
	IP       string  `json:"ip"`
	MAC      string  `json:"mac"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	MinMs    float64 `json:"min_ms"`
	AvgMs    float64 `json:"avg_ms"`
	MaxMs    float64 `json:"max_ms"`
	JitterMs float64 `json:"jitter_ms"`
}

func (r ProbeResult) LossPercent() int {
	if r.Sent == 0 {
		return 100
	}
	return int(math.Round(float64(r.Sent-r.Received) * 100 / float64(r.Sent)))
}

type Facts struct {
	Neighbours []Neighbour           `json:"neighbours"`
	Sets       map[string][]SetEntry `json:"sets"`
	Links      []LinkStats           `json:"links"`
	UptimeSec  int64                 `json:"uptime_sec"`
}

func WithDev(ns []Neighbour, dev string) []Neighbour {
	for i := range ns {
		if ns[i].Dev == "" {
			ns[i].Dev = dev
		}
	}
	return ns
}

func ParseNeighbours(raw []byte) ([]Neighbour, error) {
	var rows []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse ip neigh json: %w", err)
	}
	out := make([]Neighbour, 0, len(rows))
	for _, r := range rows {
		if r.LLAddr == "" || r.Dst == "" || strings.Contains(r.Dst, ":") {
			continue
		}
		state := ""
		if len(r.State) > 0 {
			state = r.State[0]
		}
		out = append(out, Neighbour{IP: r.Dst, MAC: strings.ToLower(r.LLAddr), Dev: r.Dev, State: state})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func ParseSet(raw []byte) ([]SetEntry, error) {
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var out []SetEntry
	for _, item := range doc.Nftables {
		var wrapper struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		}
		if json.Unmarshal(item, &wrapper) != nil || wrapper.Set == nil {
			continue
		}
		for _, e := range wrapper.Set.Elem {
			var elem struct {
				Elem struct {
					Val     string `json:"val"`
					Expires int64  `json:"expires"`
					Counter struct {
						Packets int64 `json:"packets"`
						Bytes   int64 `json:"bytes"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if json.Unmarshal(e, &elem) != nil || elem.Elem.Val == "" {
				continue
			}
			out = append(out, SetEntry{IP: elem.Elem.Val, Packets: elem.Elem.Counter.Packets,
				Bytes: elem.Elem.Counter.Bytes, Expires: elem.Elem.Expires})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func ParseLink(raw []byte, speed, duplex string) (LinkStats, error) {
	var rows []struct {
		Ifname  string `json:"ifname"`
		Stats64 struct {
			Rx map[string]int64 `json:"rx"`
			Tx map[string]int64 `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		return LinkStats{}, fmt.Errorf("parse ip link json: %v", err)
	}
	r := rows[0]
	ls := LinkStats{
		Name: r.Ifname, SpeedMbit: -1, Duplex: "unknown",
		RxPackets: r.Stats64.Rx["packets"], RxErrors: r.Stats64.Rx["errors"],
		RxDropped: r.Stats64.Rx["dropped"], RxCRC: r.Stats64.Rx["crc_errors"],
		TxPackets: r.Stats64.Tx["packets"], TxErrors: r.Stats64.Tx["errors"],
		Collisions: r.Stats64.Tx["collisions"],
	}
	if v, err := strconv.Atoi(strings.TrimSpace(speed)); err == nil && v > 0 {
		ls.SpeedMbit = v
	}
	if d := strings.TrimSpace(duplex); d == "full" || d == "half" {
		ls.Duplex = d
	}
	return ls, nil
}

var (
	arpingReply   = regexp.MustCompile(`Unicast reply from ([0-9.]+) \[([0-9A-Fa-f:]+)\]\s+([0-9.]+)ms`)
	arpingSent    = regexp.MustCompile(`Sent (\d+) probe`)
	arpingRecv    = regexp.MustCompile(`Received (\d+) response`)
	arpingWhitesp = regexp.MustCompile(`\s+`)
)

func ParseArping(ip string, out []byte) ProbeResult {
	res := ProbeResult{IP: ip}
	text := string(out)
	var rtts []float64
	for _, m := range arpingReply.FindAllStringSubmatch(text, -1) {
		if res.MAC == "" {
			res.MAC = strings.ToLower(m[2])
		}
		if v, err := strconv.ParseFloat(m[3], 64); err == nil {
			rtts = append(rtts, v)
		}
	}
	if m := arpingSent.FindStringSubmatch(text); m != nil {
		res.Sent, _ = strconv.Atoi(m[1])
	}
	if m := arpingRecv.FindStringSubmatch(text); m != nil {
		res.Received, _ = strconv.Atoi(m[1])
	} else {
		res.Received = len(rtts)
	}
	if len(rtts) > 0 {
		res.MinMs, res.MaxMs = rtts[0], rtts[0]
		sum := 0.0
		for _, v := range rtts {
			sum += v
			res.MinMs = math.Min(res.MinMs, v)
			res.MaxMs = math.Max(res.MaxMs, v)
		}
		res.AvgMs = sum / float64(len(rtts))
		variance := 0.0
		for _, v := range rtts {
			variance += (v - res.AvgMs) * (v - res.AvgMs)
		}
		res.JitterMs = math.Sqrt(variance / float64(len(rtts)))
		res.MinMs, res.AvgMs, res.MaxMs, res.JitterMs = round2(res.MinMs), round2(res.AvgMs), round2(res.MaxMs), round2(res.JitterMs)
	}
	_ = arpingWhitesp
	return res
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
