package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

func (f *firewallApplier) dhcpWatchWanted() (w nftgen.DHCPWatch, want, known bool) {
	if f.held.ruleset == nil || !f.held.working || f.guard.emergency {
		return w, false, true
	}
	switch capsOf(f.caps).Answer("nft.dhcp_watch") {
	case hostcaps.No:
		return w, false, true
	case hostcaps.Unknown:
		return w, false, false
	}
	if f.held.plan == nil {
		return w, false, false
	}
	for _, l := range f.held.plan.LANs {
		w.LANs = append(w.LANs, l.Name)
		w.Prefixes = append(w.Prefixes, l.CIDR)
		if mac := cardMAC(l.Name); mac != "" && !slices.Contains(w.OwnMACs, mac) {
			w.OwnMACs = append(w.OwnMACs, mac)
		}
	}
	if len(w.LANs) == 0 || w.Validate() != nil {
		return nftgen.DHCPWatch{}, false, true
	}
	return w, true, true
}

func cardMAC(name string) string {
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", filepath.Base(name), "address"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func (f *firewallApplier) ensureDHCPWatch(last writer) (changed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recallPlan()
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return false
	}
	w, want, known := f.dhcpWatchWanted()
	if !known {
		return false
	}
	present, intact := dhcpWatchState(nft)
	if !want {
		if present {
			_, _ = runStdin(nft, nil, "delete", "table", "inet", nftgen.DHCPWatchTable)
			log.Printf("dhcp watch: table removed")
		}
		f.dhcpBuilt, f.dhcpReset = nil, false
		return false
	}
	if f.dhcpBuilt != nil && !intact {

		g := &f.guard
		g.erasedAt = g.now()
		g.erasures++
		if last.pid != 0 {
			g.eraser = last
		}
		log.Printf("dhcp watch: table changed by someone else (%s)", writerLine(g.eraser))
		changed = true
	}
	var script string
	fresh := false
	switch {
	case !intact:
		script, fresh = w.Create(nftgen.DHCPFresh, nftgen.DHCPWindow), true
	case f.dhcpBuilt == nil:

		script = w.Sync()
	case reflect.DeepEqual(*f.dhcpBuilt, w):
		return changed
	case slices.Equal(f.dhcpBuilt.Prefixes, w.Prefixes):
		script = w.Sync()
	default:
		script, fresh = w.Create(nftgen.DHCPFresh, nftgen.DHCPWindow), true
	}
	if out, err := runStdin(nft, []byte(script), "-f", "-"); err != nil {
		log.Printf("dhcp watch: table not built: %s", firstLine(out))
		f.dhcpBuilt = nil
		if f.caps != nil {
			go f.caps.recheck(capsOf(f.caps).Digest)
		}
		return changed
	}
	if fresh {

		f.dhcpReset = false
	}
	f.dhcpBuilt = &w
	return changed
}

func dhcpWatchState(nft string) (present, intact bool) {
	list, err := runOut(nft, "-j", "list", "tables")
	if err != nil || !hasTable(list, "inet", nftgen.DHCPWatchTable) {
		return false, false
	}
	out, err := runOut(nft, "-j", "-t", "list", "table", "inet", nftgen.DHCPWatchTable)
	if err != nil {
		return false, false
	}
	body := parseShape(out).body
	return true, strings.Contains(body, "set "+nftgen.DHCPSeenSet) &&
		strings.Contains(body, "set "+nftgen.DHCPWindowSet) &&
		strings.Contains(body, "rules "+nftgen.DHCPWatchChain+" 1")
}

func (f *firewallApplier) restartDHCPWatch() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dhcpBuilt == nil {
		return
	}
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return
	}
	if out, err := runStdin(nft, []byte(f.dhcpBuilt.Restart(nftgen.DHCPWindow)), "-f", "-"); err != nil {
		log.Printf("dhcp watch: restart failed: %s", firstLine(out))
		f.dhcpBuilt = nil
		return
	}
	f.dhcpReset = true
}

type dhcpSeen struct{ mac, addr string }

func dhcpWatchRead() (seen []dhcpSeen, windowOpen, ok bool) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return nil, false, false
	}
	s, err := runOut(nft, "-j", "list", "set", "inet", nftgen.DHCPWatchTable, nftgen.DHCPSeenSet)
	if err != nil {
		return nil, false, false
	}
	w, err := runOut(nft, "-j", "list", "set", "inet", nftgen.DHCPWatchTable, nftgen.DHCPWindowSet)
	if err != nil {
		return nil, false, false
	}
	return parseSeen(s), len(setElems(w)) > 0, true
}

func setElems(out []byte) []json.RawMessage {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}
	for _, it := range doc.Nftables {
		if it.Set != nil {
			return it.Set.Elem
		}
	}
	return nil
}

func parseSeen(out []byte) []dhcpSeen {
	var res []dhcpSeen
	for _, raw := range setElems(out) {
		var e struct {
			Elem *struct {
				Val json.RawMessage `json:"val"`
			} `json:"elem"`
			Concat []string `json:"concat"`
		}
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		parts := e.Concat
		if e.Elem != nil {
			var v struct {
				Concat []string `json:"concat"`
			}
			if json.Unmarshal(e.Elem.Val, &v) != nil {
				continue
			}
			parts = v.Concat
		}
		if len(parts) != 2 {
			continue
		}
		if _, err := netip.ParseAddr(parts[1]); err != nil {
			continue
		}
		res = append(res, dhcpSeen{mac: parts[0], addr: parts[1]})
	}
	return res
}
