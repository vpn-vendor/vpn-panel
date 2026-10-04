package wggen

import (
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

type PeerState struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint,omitempty"`
	HandshakeUnix int64  `json:"handshake_unix"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

func ParseHandshakes(out []byte) map[string]int64 {
	res := map[string]int64{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		res[f[0]] = ts
	}
	return res
}

func ParseTransfer(out []byte) map[string][2]int64 {
	res := map[string][2]int64{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		rx, err1 := strconv.ParseInt(f[1], 10, 64)
		tx, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		res[f[0]] = [2]int64{rx, tx}
	}
	return res
}

func ParseEndpoints(out []byte) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		res[f[0]] = f[1]
	}
	return res
}

func ParseFwmark(out []byte) int {
	s := strings.TrimSpace(string(out))
	if s == "" || s == "off" {
		return 0
	}
	base, digits := 10, s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, digits = 16, s[2:]
	}
	v, err := strconv.ParseInt(digits, base, 64)
	if err != nil || v <= 0 || v > 0xffffffff {
		return 0
	}
	return int(v)
}

func PeerStates(handshakes []byte, transfer []byte, endpoints []byte) []PeerState {
	hs := ParseHandshakes(handshakes)
	tr := ParseTransfer(transfer)
	ep := ParseEndpoints(endpoints)
	var out []PeerState
	for key, ts := range hs {
		st := PeerState{PublicKey: key, HandshakeUnix: ts, Endpoint: ep[key]}
		if v, ok := tr[key]; ok {
			st.RxBytes, st.TxBytes = v[0], v[1]
		}
		out = append(out, st)
	}
	return out
}

const (
	ProbeLow    = vpndriver.ProbeLow
	ProbeHigh   = vpndriver.ProbeHigh
	ProbeHeader = vpndriver.ProbeHeader
)

func NextProbe(low, high int) int { return vpndriver.NextProbe(low, high) }

func TunnelMTU(pathMTU int) int { return vpndriver.TunnelMTU(pathMTU, OverheadIPv4) }
