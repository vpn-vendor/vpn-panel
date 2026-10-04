//go:build linux

package multilisten

import (
	"context"
	"net"
	"syscall"
)

func listenFreeBind(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp4", addr)
}
