package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const (
	linkLocalNMFile    = "/run/NetworkManager/conf.d/50-vpn-panel-link-local.conf"
	linkLocalNMContent = "[connection-vpn-panel-link-local]\nipv4.link-local=fallback\n"

	linkLocalNetworkdDir = "/run/systemd/network"
	linkLocalDropInName  = "vpn-panel-link-local.conf"

	linkLocalNetworkdContent = "[Network]\nLinkLocalAddressing=yes\n"

	linkLocalOwnPrefix  = "50-vpn-panel-link-local-"
	linkLocalOwnContent = "[Match]\nName=%s\n\n[Network]\nDHCP=yes\nLinkLocalAddressing=yes\n\n[DHCPv4]\nClientIdentifier=mac\n"
)

const linkLocalPollInterval = 30 * time.Second

type linkLocalHelper struct {
	renderer func() string

	rolesApplied func() bool
}

func newLinkLocalHelper() *linkLocalHelper {
	return &linkLocalHelper{
		renderer: detectRenderer,
		rolesApplied: func() bool {
			_, err := os.Stat(netplanFile)
			return err == nil
		},
	}
}

var ownIfaces = append(vpnproto.Ifaces(), qosgen.IFBDevice, qosgen.IFBTunnelDevice, netplangen.IfacePPPoE)

func cardsWithoutIPv4(ifaces []netstatus.Interface) []string {
	var out []string
	for _, i := range ifaces {
		if i.Loopback || strings.Contains(i.Name, ".") || !netplangen.ValidIfaceName(i.Name) {
			continue
		}
		own := false
		for _, n := range ownIfaces {
			if n == i.Name {
				own = true
			}
		}
		if own {
			continue
		}
		hasV4 := false
		for _, a := range i.Addresses {
			if !strings.Contains(a, ":") {
				hasV4 = true
				break
			}
		}
		if !hasV4 {
			out = append(out, i.Name)
		}
	}
	return out
}

func networkdDropIn(iface string, defIDs map[string]string) (base, dropIn string) {
	id := iface
	if v, ok := defIDs[iface]; ok && netplangen.ValidDefinitionID(v) {
		id = v
	}
	base = filepath.Join(linkLocalNetworkdDir, "10-netplan-"+id+".network")
	return base, filepath.Join(base+".d", linkLocalDropInName)
}

func networkdOwnFile(iface string) string {
	return filepath.Join(linkLocalNetworkdDir, linkLocalOwnPrefix+iface+".network")
}

func (h *linkLocalHelper) watch() {
	h.ensure()
	for range time.Tick(linkLocalPollInterval) {
		if h.rolesApplied() {
			return
		}
		h.ensure()
	}
}

func (h *linkLocalHelper) ensure() {
	if h.rolesApplied() {
		h.remove()
		return
	}
	st, err := netstatus.Collect()
	if err != nil {
		return
	}
	cards := cardsWithoutIPv4(st.Interfaces)
	if h.renderer() == netplangen.RendererNM {
		h.ensureNM(cards)
		return
	}
	h.ensureNetworkd(cards)
}

func (h *linkLocalHelper) ensureNM(cards []string) {
	if cur, err := os.ReadFile(linkLocalNMFile); err == nil && string(cur) == linkLocalNMContent { //nolint:gosec
		return
	}
	if err := durable.MkdirAll(filepath.Dir(linkLocalNMFile), 0o755); err != nil {
		log.Printf("link-local: %v", err)
		return
	}
	if err := durable.Write(linkLocalNMFile, []byte(linkLocalNMContent), 0o644); err != nil {
		log.Printf("link-local: %v", err)
		return
	}
	nmcli, err := findBinary(nmcliCandidates)
	if err != nil {
		return
	}
	_ = exec.Command(nmcli, "general", "reload", "conf").Run() //nolint:gosec

	for _, name := range cards {
		_ = exec.Command(nmcli, "-w", "1", "device", "connect", name).Run() //nolint:gosec
	}
	log.Printf("link-local: fallback address enabled for cards without IPv4 (%s)", strings.Join(cards, ","))
}

func (h *linkLocalHelper) ensureNetworkd(cards []string) {
	defIDs := currentDefinitionIDs()
	added := 0
	for _, name := range cards {
		base, dropIn := networkdDropIn(name, defIDs)
		path, content := dropIn, linkLocalNetworkdContent
		if _, err := os.Stat(base); err != nil {

			path, content = networkdOwnFile(name), fmt.Sprintf(linkLocalOwnContent, name)
		}
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := durable.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Printf("link-local: %v", err)
			continue
		}
		if err := durable.Write(path, []byte(content), 0o644); err != nil {
			log.Printf("link-local: %v", err)
			continue
		}
		added++
	}
	if added == 0 {
		return
	}
	networkdReload()
	log.Printf("link-local: fallback address enabled for %d card(s) without IPv4", added)
}

func (h *linkLocalHelper) remove() {
	if _, err := os.Stat(linkLocalNMFile); err == nil {
		if err := durable.Remove(linkLocalNMFile); err != nil {
			log.Printf("link-local: %v", err)
		} else if nmcli, err := findBinary(nmcliCandidates); err == nil {
			_ = exec.Command(nmcli, "general", "reload", "conf").Run() //nolint:gosec
		}
	}
	matches, _ := filepath.Glob(filepath.Join(linkLocalNetworkdDir, "10-netplan-*.network.d", linkLocalDropInName))
	own, _ := filepath.Glob(filepath.Join(linkLocalNetworkdDir, linkLocalOwnPrefix+"*.network"))
	matches = append(matches, own...)
	removed := 0
	for _, dropIn := range matches {
		if err := durable.Remove(dropIn); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("link-local: %v", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		networkdReload()
		log.Printf("link-local: fallback address removed from %d card(s)", removed)
	}
}

func networkdReload() {
	networkctl, err := findBinary([]string{"/usr/bin/networkctl", "/bin/networkctl"})
	if err != nil {
		return
	}
	if out, err := exec.Command(networkctl, "reload").CombinedOutput(); err != nil { //nolint:gosec
		log.Printf("link-local: networkctl reload: %s", firstLine(out))
	}
}
