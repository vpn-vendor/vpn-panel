package pathprobe

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
)

const DSCPEF = 46 << 2

const (
	icmpEcho      = 8
	icmpEchoReply = 0
	payload       = "vpn-panel-path-probe"
)

var ErrForbidden = errors.New("отправка запрещена правилом выхода")

var ErrTimeout = errors.New("ответа нет")

func Ping(target net.IP, seq uint16, timeout time.Duration) (time.Duration, error) {
	ip4 := target.To4()
	if ip4 == nil {
		return 0, errors.New("цель не IPv4")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	defer func() { _ = syscall.Close(fd) }()
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, DSCPEF)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	pkt := buildEcho(seq)
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], ip4)
	start := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return 0, ErrForbidden
		}
		return 0, err
	}
	buf := make([]byte, 1500)
	deadline := start.Add(timeout)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return 0, ErrTimeout
			}
			return 0, err
		}

		if n >= 8 && buf[0] == icmpEchoReply && binary.BigEndian.Uint16(buf[6:8]) == seq {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			return 0, ErrTimeout
		}
	}
}

func buildEcho(seq uint16) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = icmpEcho
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], checksum(b))
	return b
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum) //nolint:gosec
}
