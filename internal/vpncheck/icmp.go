package vpncheck

import (
	"encoding/binary"
	"errors"
	"math"
	"time"
)

const (
	icmpEchoRequest  = 8
	icmpEchoReply    = 0
	icmpTimeExceeded = 11
)

const HeaderLen = 8

func EchoRequest(id, seq uint16, payloadLen int) []byte {
	if payloadLen < 0 {
		payloadLen = 0
	}
	b := make([]byte, HeaderLen+payloadLen)
	b[0] = icmpEchoRequest
	b[1] = 0
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	for i := HeaderLen; i < len(b); i++ {
		b[i] = byte(i)
	}
	binary.BigEndian.PutUint16(b[2:4], checksum(b))
	return b
}

type ReplyKind int

const (
	ReplyOther ReplyKind = iota

	ReplyEcho

	ReplyExpired
)

var ErrShort = errors.New("служебное сообщение короче заголовка")

func ParseReply(data []byte, id uint16) (ReplyKind, uint16, error) {
	if len(data) < HeaderLen {
		return ReplyOther, 0, ErrShort
	}
	switch data[0] {
	case icmpEchoReply:
		gotID := binary.BigEndian.Uint16(data[4:6])
		if gotID != id {
			return ReplyOther, 0, nil
		}
		return ReplyEcho, binary.BigEndian.Uint16(data[6:8]), nil

	case icmpTimeExceeded:

		inner := data[HeaderLen:]
		if len(inner) < 20 {
			return ReplyOther, 0, ErrShort
		}
		ihl := int(inner[0]&0x0f) * 4
		if ihl < 20 || len(inner) < ihl+HeaderLen {
			return ReplyOther, 0, ErrShort
		}
		orig := inner[ihl:]
		if orig[0] != icmpEchoRequest {
			return ReplyOther, 0, nil
		}
		if binary.BigEndian.Uint16(orig[4:6]) != id {
			return ReplyOther, 0, nil
		}
		return ReplyExpired, binary.BigEndian.Uint16(orig[6:8]), nil
	}
	return ReplyOther, 0, nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

type Stats struct {
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	LossPct     float64 `json:"loss_pct"`
	AvgMs       float64 `json:"avg_ms"`
	MinMs       float64 `json:"min_ms"`
	MaxMs       float64 `json:"max_ms"`
	JitterMs    float64 `json:"jitter_ms"`
	MaxBurst    int     `json:"max_burst"`
	BurstEvents int     `json:"burst_events"`
}

func Bursts(sent int, received map[int]bool) (maxBurst, events int) {
	run := 0
	for seq := 0; seq < sent; seq++ {
		if received[seq] {
			if run >= 2 {
				events++
			}
			if run > maxBurst {
				maxBurst = run
			}
			run = 0
			continue
		}
		run++
	}
	if run >= 2 {
		events++
	}
	if run > maxBurst {
		maxBurst = run
	}
	return maxBurst, events
}

func Summarize(sent int, rtts []time.Duration) Stats {
	st := Stats{Sent: sent, Received: len(rtts)}
	if sent > 0 {
		st.LossPct = float64(sent-len(rtts)) * 100 / float64(sent)
	}
	if len(rtts) == 0 {
		return st
	}
	var sum, jitterSum float64
	st.MinMs = math.MaxFloat64

	prevMs, havePrev := 0.0, false
	for _, d := range rtts {
		ms := float64(d) / float64(time.Millisecond)
		sum += ms
		if ms < st.MinMs {
			st.MinMs = ms
		}
		if ms > st.MaxMs {
			st.MaxMs = ms
		}
		if havePrev {
			jitterSum += math.Abs(ms - prevMs)
		}
		prevMs, havePrev = ms, true
	}
	st.AvgMs = sum / float64(len(rtts))
	if len(rtts) > 1 {
		st.JitterMs = jitterSum / float64(len(rtts)-1)
	}
	return st
}
