package rtnl

import (
	"encoding/binary"
	"errors"
	"syscall"
)

const (
	rtmGetQdisc = 38
	rtmNewQdisc = 36
	sizeofTcmsg = 20

	tcaKind     = 1
	tcaStats2   = 7
	tcaStatsApp = 4

	cakeStatsTinStats = 10
	tinSentPackets    = 2
	tinDroppedPackets = 4
	tinTargetUs       = 13
	tinIntervalUs     = 14
	tinPeakDelayUs    = 18
	tinAvgDelayUs     = 19
	tinBaseDelayUs    = 20

	nlaFNested  = 0x8000
	nlaTypeMask = 0x3fff
	nlmsgHdrLen = 16
)

type Tin struct {
	SentPackets    uint32
	DroppedPackets uint32
	PeakDelayUs    uint32
	AvgDelayUs     uint32
	BaseDelayUs    uint32

	TargetUs   uint32
	IntervalUs uint32
}

type Qdisc struct {
	IfIndex int
	Kind    string
	Tins    []Tin
}

func DumpQdiscs() ([]Qdisc, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	const reqLen = nlmsgHdrLen + sizeofTcmsg
	req := make([]byte, reqLen)
	binary.LittleEndian.PutUint32(req[0:], reqLen)
	binary.LittleEndian.PutUint16(req[4:], rtmGetQdisc)
	binary.LittleEndian.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:], 1)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	var data []byte
	buf := make([]byte, 64<<10)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		data = append(data, buf[:n]...)
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		done := false
		for i := range msgs {
			if t := msgs[i].Header.Type; t == syscall.NLMSG_DONE || t == syscall.NLMSG_ERROR {
				done = true
			}
		}
		if done {
			break
		}
	}
	return ParseQdiscDump(data)
}

func ParseQdiscDump(data []byte) ([]Qdisc, error) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var out []Qdisc
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			return out, nil
		case syscall.NLMSG_ERROR:
			return out, errors.New("rtnetlink: ошибка в ответе дампа очередей")
		case rtmNewQdisc:
			if len(m.Data) < sizeofTcmsg {
				continue
			}
			q := Qdisc{IfIndex: int(int32(binary.LittleEndian.Uint32(m.Data[4:8])))} //nolint:gosec
			for _, a := range attrs(m.Data[sizeofTcmsg:]) {
				switch a.typ {
				case tcaKind:
					q.Kind = string(trimNul(a.val))
				case tcaStats2:
					for _, s := range attrs(a.val) {
						if s.typ == tcaStatsApp {
							q.Tins = parseCakeTins(s.val)
						}
					}
				}
			}
			out = append(out, q)
		}
	}
	return out, nil
}

func parseCakeTins(app []byte) []Tin {
	var tins []Tin
	for _, a := range attrs(app) {
		if a.typ != cakeStatsTinStats {
			continue
		}
		for _, t := range attrs(a.val) {
			idx := int(t.typ) - 1
			if idx < 0 || idx > 15 {
				continue
			}
			for len(tins) <= idx {
				tins = append(tins, Tin{})
			}
			tin := &tins[idx]
			for _, f := range attrs(t.val) {
				if len(f.val) < 4 {
					continue
				}
				v := binary.LittleEndian.Uint32(f.val)
				switch f.typ {
				case tinSentPackets:
					tin.SentPackets = v
				case tinDroppedPackets:
					tin.DroppedPackets = v
				case tinTargetUs:
					tin.TargetUs = v
				case tinIntervalUs:
					tin.IntervalUs = v
				case tinPeakDelayUs:
					tin.PeakDelayUs = v
				case tinAvgDelayUs:
					tin.AvgDelayUs = v
				case tinBaseDelayUs:
					tin.BaseDelayUs = v
				}
			}
		}
	}
	return tins
}

type attr struct {
	typ uint16
	val []byte
}

func attrs(b []byte) []attr {
	var out []attr
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4])
		if l < 4 || l > len(b) {
			break
		}
		out = append(out, attr{typ: t & nlaTypeMask, val: b[4:l]})
		next := (l + 3) &^ 3
		if next > len(b) {
			break
		}
		b = b[next:]
	}
	return out
}

var _ = nlaFNested
