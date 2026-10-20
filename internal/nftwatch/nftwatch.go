package nftwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

type Event struct {
	PID  int
	Comm string

	Overflow bool
}

const queueLen = 8

func Subscribe(ctx context.Context) (<-chan Event, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nftwatch: сокет netfilter: %w", err)
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTABLES - 1)}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nftwatch: подписка на группу nftables: %w", err)
	}
	return watch(ctx, fd)
}

func watch(ctx context.Context, fd int) (<-chan Event, error) {
	f := os.NewFile(uintptr(fd), "nftables-events")
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	out := make(chan Event, queueLen)
	stop := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		_ = f.Close()
	}()
	go func() {
		defer close(out)
		defer func() { _ = f.Close() }()
		defer close(stop)

		buf := make([]byte, os.Getpagesize())
		loop(ctx, func() ([]byte, error) { return recvDatagram(rc, &buf) }, out)
	}()
	return out, nil
}

func recvDatagram(rc syscall.RawConn, buf *[]byte) ([]byte, error) {
	var (
		data []byte
		rerr error
	)
	err := rc.Read(func(fd uintptr) bool {
		for {
			size, _, err := unix.Recvfrom(int(fd), nil, unix.MSG_PEEK|unix.MSG_TRUNC)
			if err == nil {
				if size > len(*buf) {
					*buf = make([]byte, size)
				}
				var from unix.Sockaddr
				size, from, err = unix.Recvfrom(int(fd), *buf, 0)
				if err == nil {
					if nl, ok := from.(*unix.SockaddrNetlink); ok && nl.Pid != 0 {
						continue
					}
					data = (*buf)[:size]
					return true
				}
			}
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.EAGAIN):
				return false
			}
			rerr = err
			return true
		}
	})
	if err != nil {
		return nil, err
	}
	return data, rerr
}

func loop(ctx context.Context, recv func() ([]byte, error), out chan Event) {
	for ctx.Err() == nil {
		data, err := recv()
		switch {
		case err == nil:
			evs, perr := parse(data)
			if perr != nil {

				evs = append(evs, Event{Overflow: true})
			}
			deliver(ctx, out, evs)
		case errors.Is(err, unix.ENOBUFS):

			deliver(ctx, out, []Event{{Overflow: true}})
		default:
			if ctx.Err() == nil {
				deliver(ctx, out, []Event{{Overflow: true}})
			}
			return
		}
	}
}

func deliver(ctx context.Context, out chan Event, evs []Event) {
	evs = merge(evs, cap(out))
	for i := range evs {
		select {
		case out <- evs[i]:
			continue
		default:
		}
		for _, e := range merge(append(drain(out), evs[i:]...), cap(out)) {
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		return
	}
}

func drain(out chan Event) []Event {
	var q []Event
	for {
		select {
		case e := <-out:
			q = append(q, e)
		default:
			return q
		}
	}
}

func merge(evs []Event, limit int) []Event {
	limit = max(limit, 1)
	overflow, bare := false, false
	var named []Event
	for _, e := range evs {
		overflow = overflow || e.Overflow
		if e.PID == 0 && e.Comm == "" {
			bare = bare || !e.Overflow
			continue
		}
		c := Event{PID: e.PID, Comm: e.Comm}
		named = append(slices.DeleteFunc(named, func(x Event) bool { return x == c }), c)
		if len(named) > limit {
			named = named[1:]
			overflow = true
		}
	}
	if overflow && len(named) >= limit {
		named = named[len(named)-limit+1:]
	}
	var res []Event
	if overflow {
		res = append(res, Event{Overflow: true})
	}
	res = append(res, named...)
	if len(res) == 0 && bare {
		res = append(res, Event{})
	}
	return res
}
