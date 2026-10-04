package rtnl

import (
	"encoding/binary"
	"errors"
	"syscall"
)

const (
	iflaStats64 = 23

	offRxBytes = 16
	offTxBytes = 24
	minStats64 = 32
)

type Link struct {
	Index    int
	Name     string
	Up       bool
	RxBytes  uint64
	TxBytes  uint64
	HasStats bool
}

func Dump() ([]Link, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return ParseDump(data)
}

func ParseDump(data []byte) ([]Link, error) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var out []Link
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			return out, nil
		case syscall.NLMSG_ERROR:
			return out, errors.New("rtnetlink: ошибка в ответе дампа")
		case syscall.RTM_NEWLINK:
			if l, ok := parseLink(m); ok {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func parseLink(m *syscall.NetlinkMessage) (Link, bool) {
	if len(m.Data) < syscall.SizeofIfInfomsg {
		return Link{}, false
	}

	index := int(int32(binary.LittleEndian.Uint32(m.Data[4:8]))) //nolint:gosec
	flags := binary.LittleEndian.Uint32(m.Data[8:12])
	l := Link{Index: index, Up: flags&syscall.IFF_UP != 0}
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return Link{}, false
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case syscall.IFLA_IFNAME:
			l.Name = string(trimNul(a.Value))
		case iflaStats64:
			if len(a.Value) >= minStats64 {
				l.RxBytes = binary.LittleEndian.Uint64(a.Value[offRxBytes:])
				l.TxBytes = binary.LittleEndian.Uint64(a.Value[offTxBytes:])
				l.HasStats = true
			}
		}
	}
	return l, l.Name != ""
}

func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

type EventKind int

const (
	LinkChanged EventKind = iota
	LinkRemoved
	LinkOverflow
)

type Event struct {
	Kind  EventKind
	Index int
	Name  string
}

type Watcher struct {
	fd   int
	read func(fd int, b []byte) (int, error)
}

func Watch() (*Watcher, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 << (syscall.RTNLGRP_LINK - 1)}
	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &Watcher{fd: fd, read: syscall.Read}, nil
}

func (w *Watcher) Next(buf []byte) ([]Event, error) {
	n, err := w.read(w.fd, buf)
	if errors.Is(err, syscall.ENOBUFS) {
		return []Event{{Kind: LinkOverflow}}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseEvents(buf[:n])
}

func ParseEvents(data []byte) ([]Event, error) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var out []Event
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			l, ok := parseLink(m)
			if !ok {
				continue
			}
			kind := LinkChanged
			if m.Header.Type == syscall.RTM_DELLINK {
				kind = LinkRemoved
			}
			out = append(out, Event{Kind: kind, Index: l.Index, Name: l.Name})
		}
	}
	return out, nil
}

func (w *Watcher) Close() error { return syscall.Close(w.fd) }
