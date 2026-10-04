package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const tunnelRouteTable = "51820"

const lastResortMetric = "4294967295"

func ensureKillRoutes(mark int) error {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return err
	}
	if out, err := exec.Command(ipBin, "-4", "route", "replace", "unreachable", "default", "metric", lastResortMetric, "table", tunnelRouteTable).CombinedOutput(); err != nil { //nolint:gosec
		return fmt.Errorf("запасной маршрут канала: %s", firstLine(out))
	}
	rules, _ := exec.Command(ipBin, "-4", "rule", "show").Output() //nolint:gosec
	markHex := fmt.Sprintf("0x%x", mark)
	if !strings.Contains(string(rules), "fwmark "+markHex+" lookup "+tunnelRouteTable) {
		if out, err := exec.Command(ipBin, "-4", "rule", "add", "not", "fwmark", strconv.Itoa(mark), "table", tunnelRouteTable, "pref", "32765").CombinedOutput(); err != nil { //nolint:gosec
			return fmt.Errorf("правило метки: %s", firstLine(out))
		}
	}
	if !strings.Contains(string(rules), "suppress_prefixlength 0") {
		if out, err := exec.Command(ipBin, "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0", "pref", "32764").CombinedOutput(); err != nil { //nolint:gosec
			return fmt.Errorf("правило основной таблицы: %s", firstLine(out))
		}
	}

	if sysctl, err := findBinary([]string{"/usr/sbin/sysctl", "/sbin/sysctl"}); err == nil {
		_ = exec.Command(sysctl, "-q", "-w", "net.ipv4.conf.all.src_valid_mark=1").Run() //nolint:gosec
	}
	return nil
}

func ensureTunnelRoutes(iface string, mark int) error {
	if err := ensureKillRoutes(mark); err != nil {
		return err
	}
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return err
	}
	if out, err := exec.Command(ipBin, "-4", "route", "replace", "default", "dev", iface, "table", tunnelRouteTable).CombinedOutput(); err != nil { //nolint:gosec
		return fmt.Errorf("маршрут канала: %s", firstLine(out))
	}
	return nil
}

func removeTunnelRoutes() {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return
	}
	for i := 0; i < 3; i++ {
		rules, _ := exec.Command(ipBin, "-4", "rule", "show").Output() //nolint:gosec
		if !strings.Contains(string(rules), "lookup "+tunnelRouteTable) {
			break
		}
		_ = exec.Command(ipBin, "-4", "rule", "del", "table", tunnelRouteTable).Run() //nolint:gosec
	}
	for i := 0; i < 3; i++ {
		rules, _ := exec.Command(ipBin, "-4", "rule", "show").Output() //nolint:gosec
		if !strings.Contains(string(rules), "suppress_prefixlength 0") {
			break
		}
		_ = exec.Command(ipBin, "-4", "rule", "del", "table", "main", "suppress_prefixlength", "0").Run() //nolint:gosec
	}
	_ = exec.Command(ipBin, "-4", "route", "flush", "table", tunnelRouteTable).Run() //nolint:gosec
}

func tunnelRoutesPresent(iface string) bool {
	ipBin, err := findBinary(ipCandidates)
	if err != nil {
		return true
	}
	routes, err := exec.Command(ipBin, "-4", "route", "show", "table", tunnelRouteTable).Output() //nolint:gosec
	if err != nil || !strings.Contains(string(routes), "dev "+iface) {
		return false
	}
	if !strings.Contains(string(routes), "unreachable default") {
		return false
	}
	rules, _ := exec.Command(ipBin, "-4", "rule", "show").Output() //nolint:gosec
	return strings.Contains(string(rules), "lookup "+tunnelRouteTable) && strings.Contains(string(rules), "suppress_prefixlength 0")
}
