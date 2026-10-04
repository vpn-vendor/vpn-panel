//go:build !linux

package multilisten

import "net"

func listenFreeBind(addr string) (net.Listener, error) {
	return net.Listen("tcp4", addr)
}
