package main

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type icmpFlood struct {
	mu       sync.Mutex
	id       uint16
	first    bool
	deadline time.Time
	closed   bool

	stopSet chan struct{}
	once    sync.Once
}

func (f *icmpFlood) ReadFrom(b []byte) (int, net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, nil, net.ErrClosed
	}
	if !f.deadline.IsZero() && !time.Now().Before(f.deadline) {
		return 0, nil, os.ErrDeadlineExceeded
	}
	if !f.first {
		f.first = true
		reply := []byte{0, 0, 0, 0, 0, 0, 0, 1}
		binary.BigEndian.PutUint16(reply[4:6], f.id)
		return copy(b, reply), nil, nil
	}
	return copy(b, []byte{0, 0, 0, 0, 0xde, 0xad, 0, 1}), nil, nil
}

func (f *icmpFlood) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = t
	if !t.After(time.Now()) {
		f.once.Do(func() { close(f.stopSet) })
	}
	return nil
}

func (f *icmpFlood) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.once.Do(func() { close(f.stopSet) })
	return nil
}

func TestReplyReaderStopsUnderForeignFlood(t *testing.T) {
	const id = 0x1234
	f := &icmpFlood{id: id, stopSet: make(chan struct{})}
	inReply := make(chan struct{})
	stop := readReplies(f, id, time.Second, func(uint16) {
		close(inReply)
		<-f.stopSet
	})
	<-inReply
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("читатель ответов не остановился: чужие пакеты отодвигают срок чтения")
	}
}
