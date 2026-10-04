//go:build !linux

package agentrpc

import "net"

func peerUID(net.Conn) (uint32, bool) { return 0, false }
