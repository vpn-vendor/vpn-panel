package legacyvpn

import (
	"slices"
	"strings"
)

const (
	NetplanDir     = netplanDir
	ScriptNetplan  = scriptNetplan
	UnitDir        = unitDir
	UdevRule       = udevRule
	MountUSB       = mountUSB
	OpenVPNConf    = openvpnConf
	WireGuardConf  = wireguardConf
	OpenVPNDir     = "/etc/openvpn"
	WireGuardDir   = "/etc/wireguard"
	RulesV4        = rulesV4
	RulesV6        = "/etc/iptables/rules.v6"
	Sudoers        = sudoersFile
	BotSudoers     = "/etc/sudoers.d/telegram_bot"
	Crontab        = crontabFile
	SysctlConf     = "/etc/sysctl.conf"
	OpenVPNDefault = "/etc/default/openvpn"
	PPPoEPeer      = "/etc/ppp/peers/dsl-provider"
	WebCrontab     = "/var/spool/cron/crontabs/www-data"
	TerminalUnit   = terminalUnit
	ScriptName     = scriptName

	OpenVPNUnit = "openvpn.service"
)

const (
	MarkerNetplan  = "netplan_file"
	MarkerUdevRule = "udev_rule"
	MarkerMountUSB = "script_mount_usb"
)

const PPPoECommand = "dsl-provider"

func SudoersLines() []string {
	return []string{
		"www-data ALL=(root) NOPASSWD: /usr/bin/id",
		"www-data ALL=(ALL) NOPASSWD: ALL",
		"www-data ALL=(ALL) NOPASSWD: /bin/systemctl",
	}
}

func SysctlKeys() []string {
	return []string{"net.ipv4.ip_forward", "net.netfilter.nf_conntrack_udp_timeout_stream"}
}

type Tunnel struct{ Unit, Conf string }

func Tunnels() []Tunnel {
	return []Tunnel{
		{"openvpn@client1.service", openvpnConf},
		{"wg-quick@tun0.service", wireguardConf},
	}
}

type Daemon struct {
	Name         string
	Unit         string
	Marker       string
	Script       string
	ScriptMarker string
}

func Daemons() []Daemon {
	out := make([]Daemon, 0, len(ownUnits))
	for _, u := range ownUnits {
		d := Daemon{Name: u.name, Unit: u.name + ".service", Marker: "unit_" + u.name}
		for _, s := range ownScripts {
			if s.id == "script_"+u.name {
				d.Script, d.ScriptMarker = s.path, s.id
			}
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Daemon) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func PPPoECronLines(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if callsPon(t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func callsPon(t string) bool {
	if t == "" || t[0] == '#' {
		return false
	}
	f := strings.Fields(t)
	for i := 0; i+1 < len(f); i++ {
		if (f[i] == "pon" || strings.HasSuffix(f[i], "/pon")) && f[i+1] == PPPoECommand {
			return true
		}
	}
	return false
}
