package main

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

const (
	leaseDir   = "/run/systemd/netif/leases"
	nmStateDir = "/run/NetworkManager/devices"
)

func fillDHCPServers(st *netstatus.Status, networkd, nm string) {
	if st == nil {
		return
	}
	for i := range st.Interfaces {
		ifc, err := net.InterfaceByName(st.Interfaces[i].Name)
		if err != nil {
			continue
		}
		idx := strconv.Itoa(ifc.Index)
		srv := leaseServer(filepath.Join(networkd, idx), "SERVER_ADDRESS")
		if srv == "" {
			srv = leaseServer(filepath.Join(nm, idx), "dhcp4.dhcp_server_identifier")
		}
		st.Interfaces[i].DHCPServer = srv
	}
}

func leaseServer(path, key string) string {
	fh, err := os.Open(path) //nolint:gosec
	if err != nil {
		return ""
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || k != key {
			continue
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil && a.Is4() {
			return a.String()
		}
	}
	return ""
}
