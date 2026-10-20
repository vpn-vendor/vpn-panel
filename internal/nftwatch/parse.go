package nftwatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

const sizeofNfgenmsg = 4

const attrTypeMask = ^uint16(unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)

func parse(b []byte) ([]Event, error) {
	var out []Event
	for len(b) > 0 {
		if len(b) < unix.NLMSG_HDRLEN {
			return out, fmt.Errorf("nftwatch: усечённый заголовок сообщения: %d байт", len(b))
		}
		l := int(binary.NativeEndian.Uint32(b))
		if l < unix.NLMSG_HDRLEN || l > len(b) {
			return out, fmt.Errorf("nftwatch: длина сообщения %d при остатке %d", l, len(b))
		}
		ev, ok, err := message(binary.NativeEndian.Uint16(b[4:]), b[unix.NLMSG_HDRLEN:l])
		if err != nil {
			return out, err
		}
		if ok {
			out = append(out, ev)
		}

		b = b[min(align(l, unix.NLMSG_ALIGNTO), len(b)):]
	}
	return out, nil
}

func message(typ uint16, body []byte) (Event, bool, error) {

	if typ>>8 != unix.NFNL_SUBSYS_NFTABLES {
		return Event{}, false, nil
	}
	if len(body) < sizeofNfgenmsg {
		return Event{}, false, errors.New("nftwatch: сообщение nftables без nfgenmsg")
	}
	if typ&0xff != unix.NFT_MSG_NEWGEN {
		return Event{}, true, nil
	}
	ev, err := genAttrs(body[sizeofNfgenmsg:])
	return ev, err == nil, err
}

func genAttrs(b []byte) (Event, error) {
	var ev Event
	for len(b) > 0 {
		if len(b) < unix.NLA_HDRLEN {
			return Event{}, fmt.Errorf("nftwatch: усечённый атрибут: %d байт", len(b))
		}
		l := int(binary.NativeEndian.Uint16(b))
		if l < unix.NLA_HDRLEN || l > len(b) {
			return Event{}, fmt.Errorf("nftwatch: длина атрибута %d при остатке %d", l, len(b))
		}
		val := b[unix.NLA_HDRLEN:l]
		switch binary.NativeEndian.Uint16(b[2:]) & attrTypeMask {
		case unix.NFTA_GEN_PROC_PID:
			if len(val) == 4 {
				if pid := binary.BigEndian.Uint32(val); pid <= math.MaxInt32 {
					ev.PID = int(pid)
				}
			}
		case unix.NFTA_GEN_PROC_NAME:
			if n := len(val); n > 0 && val[n-1] == 0 {
				ev.Comm = string(val[:bytes.IndexByte(val, 0)])
			}
		}
		b = b[min(align(l, unix.NLA_ALIGNTO), len(b)):]
	}
	return ev, nil
}

func align(n, to int) int { return (n + to - 1) &^ (to - 1) }
