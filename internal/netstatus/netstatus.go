package netstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Status struct {
	Interfaces    []Interface `json:"interfaces"`
	DefaultRoutes []Route     `json:"default_routes"`
}

type Interface struct {
	Name string `json:"name"`

	MAC string `json:"mac,omitempty"`

	Presented string   `json:"presented_mac,omitempty"`
	State     string   `json:"state"`
	MTU       int      `json:"mtu"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`

	DHCPServer string `json:"dhcp_server,omitempty"`
}

type Route struct {
	Via    string `json:"via"`
	Dev    string `json:"dev"`
	Metric int    `json:"metric,omitempty"`
}

var ipBinaryCandidates = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"}

func findIPBinary() (string, error) {
	for _, p := range ipBinaryCandidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("iproute2 binary not found in fixed locations")
}

func Collect() (*Status, error) {
	ipBin, err := findIPBinary()
	if err != nil {
		return nil, err
	}

	addrOut, err := exec.Command(ipBin, "-json", "addr", "show").Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("ip addr show: %w", err)
	}
	routeOut, err := exec.Command(ipBin, "-json", "route", "show").Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("ip route show: %w", err)
	}
	return Parse(addrOut, routeOut)
}

type ipAddr struct {
	Ifname    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	Operstate string   `json:"operstate"`
	Address   string   `json:"address"`
	PermAddr  string   `json:"permaddr"`
	AddrInfo  []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
	} `json:"addr_info"`
	LinkType string `json:"link_type"`
}

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  int    `json:"metric"`
}

func Parse(addrJSON, routeJSON []byte) (*Status, error) {
	var addrs []ipAddr
	if err := json.Unmarshal(addrJSON, &addrs); err != nil {
		return nil, fmt.Errorf("parse ip addr json: %w", err)
	}
	var routes []ipRoute
	if err := json.Unmarshal(routeJSON, &routes); err != nil {
		return nil, fmt.Errorf("parse ip route json: %w", err)
	}

	status := &Status{
		Interfaces:    make([]Interface, 0, len(addrs)),
		DefaultRoutes: []Route{},
	}
	for _, a := range addrs {
		iface := Interface{
			Name:      a.Ifname,
			State:     a.Operstate,
			MTU:       a.MTU,
			Loopback:  a.LinkType == "loopback",
			Addresses: []string{},
		}
		if !iface.Loopback {
			iface.MAC = a.Address
			if a.PermAddr != "" && a.PermAddr != a.Address {
				iface.MAC, iface.Presented = a.PermAddr, a.Address
			}
		}
		for _, ai := range a.AddrInfo {
			iface.Addresses = append(iface.Addresses,
				fmt.Sprintf("%s/%d", ai.Local, ai.Prefixlen))
		}
		status.Interfaces = append(status.Interfaces, iface)
	}
	for _, r := range routes {
		if r.Dst != "default" {
			continue
		}
		status.DefaultRoutes = append(status.DefaultRoutes, Route{
			Via: r.Gateway, Dev: r.Dev, Metric: r.Metric,
		})
	}
	return status, nil
}

type Neighbor struct {
	IP  string `json:"ip"`
	Dev string `json:"dev"`
	MAC string `json:"mac"`
}

type ipNeigh struct {
	Dst    string `json:"dst"`
	Dev    string `json:"dev"`
	LLAddr string `json:"lladdr"`
}

func CollectNeighbors() ([]Neighbor, error) {
	ipBin, err := findIPBinary()
	if err != nil {
		return nil, err
	}

	out, err := exec.Command(ipBin, "-json", "neigh", "show").Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("ip neigh show: %w", err)
	}
	return ParseNeighbors(out)
}

func ParseNeighbors(raw []byte) ([]Neighbor, error) {
	var rows []ipNeigh
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse ip neigh json: %w", err)
	}
	out := []Neighbor{}
	for _, r := range rows {
		if r.LLAddr == "" {
			continue
		}
		out = append(out, Neighbor{IP: r.Dst, Dev: r.Dev, MAC: strings.ToLower(r.LLAddr)})
	}
	return out, nil
}
