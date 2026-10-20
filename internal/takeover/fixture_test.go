package takeover

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const (
	scriptNetplanYAML = `network:
  version: 2
  renderer: networkd
  ethernets:
    ens2:
      dhcp4: true
    ens3:
      addresses: [192.168.11.1/24]
      optional: true
`
	cloudInitYAML = `network:
  version: 2
  ethernets:
    ens2:
      dhcp4: true
`
	panelNetplanYAML = `network:
  version: 2
  ethernets:
    ens3:
      addresses: [192.168.11.1/24]
`
	pingUnit = `[Unit]
Description=Ping Daemon

[Service]
ExecStart=/usr/local/bin/ping_daemon.sh
Restart=always
User=root
`
	mtuUnit = `[Unit]
Description=VPN MTU and TCPMSS Fix Daemon

[Service]
ExecStart=/usr/local/bin/vpn_mtu_daemon.sh
Restart=always
User=root
`
	botUnit = `[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/bot_source
ExecStart=/var/www/html/bot_source/venv/bin/python /var/www/html/bot_source/bot.py
Restart=always
`
	updateMetricsUnit = "[Service]\nExecStart=/usr/bin/python3 /var/www/html/api/update_metrics_daemon.py\nUser=www-data\n"
	networkLoadUnit   = "[Service]\nExecStart=/usr/bin/python3 /var/www/html/api/update_network_load.py\nUser=www-data\n"
	homeMetricsUnit   = "[Service]\nExecStart=/usr/bin/python3 /var/www/html/api/home_metrics_daemon.py\nUser=www-data\n"
	udevRuleText      = `ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[b-z][0-9]*", ENV{ID_BUS}=="usb", RUN+="/usr/local/bin/mount-usb.sh add %k"
ACTION=="remove", SUBSYSTEM=="block", KERNEL=="sd[b-z][0-9]*", ENV{ID_BUS}=="usb", RUN+="/usr/local/bin/mount-usb.sh remove %k"
`
	resolvedScript = "# Файл автоматически сгенерирован скриптом vpn.sh\n[Resolve]\nFallbackDNS=8.8.8.8 1.1.1.1\n"
	sudoersStock   = `Defaults	env_reset
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
`
	sudoersLines = `www-data ALL=(root) NOPASSWD: /usr/bin/id
www-data ALL=(ALL) NOPASSWD: ALL
www-data ALL=(ALL) NOPASSWD: /bin/systemctl
`

	sudoersScript = sudoersStock + sudoersLines + sudoersLines
	sudoersBot    = "www-data ALL=NOPASSWD: /bin/systemctl is-active telegram_bot.service, /bin/systemctl start telegram_bot.service\n"
	crontabStock  = `SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
`
	cronReboot = "@reboot root sleep 20 && /usr/bin/pon dsl-provider"
	cronMinute = "* * * * * root pgrep -f 'pppd call dsl-provider' > /dev/null || /usr/bin/pon dsl-provider"
	rulesVPN   = `*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i ens3 -o tun0 -j ACCEPT
-A FORWARD -i tun0 -o ens3 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ens3 -o ens2 -j REJECT --reject-with icmp-net-unreachable
COMMIT
*nat
-A POSTROUTING -s 192.168.11.0/24 -o tun0 -j MASQUERADE
COMMIT
`
	rulesDirect = `*filter
:FORWARD DROP [0:0]
-A FORWARD -i ens3 -o ens2 -j ACCEPT
COMMIT
*nat
-A POSTROUTING -s 192.168.11.0/24 -o ens2 -j MASQUERADE
COMMIT
`
	rulesV6Open = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`
	rulesV6Drop = `*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -i ens3 -o ens2 -j DROP
COMMIT
`
	sysctlScript = `net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=120
`
	openvpnDefault = "#AUTOSTART=\"none\"\nAUTOSTART=\"all\"\n"
	peerText       = "plugin rp-pppoe.so ens2\nuser \"office\"\npersist\n"
	webCrontab     = "* * * * * /usr/bin/python3 /var/www/html/api/update_network_metrics.py\n"
	installerYAML  = `# This is the network config written by 'subiquity'
network:
  ethernets:
    ens3:
      dhcp4: true
  version: 2
`
)

const ownNetplan = "99-vpn-panel.yaml"

func homeOf(user string) string { return "/home/" + user + "/vpn.sh" }

var homeScript = homeOf("office")

var common = map[string]string{
	legacyvpn.ScriptNetplan:                               scriptNetplanYAML,
	"/etc/netplan/backup_2026-10-19_133534/50-cloud.yaml": cloudInitYAML,
	"/etc/netplan/" + ownNetplan:                          panelNetplanYAML,
	legacyvpn.UdevRule:                                    udevRuleText,
	legacyvpn.MountUSB:                                    "#!/bin/bash\n",
	"/etc/systemd/resolved.conf":                          resolvedScript,
	legacyvpn.Crontab:                                     crontabStock,
	legacyvpn.SysctlConf:                                  sysctlScript,
	legacyvpn.Sudoers:                                     sudoersStock,
}

var vpnMode = map[string]string{
	"/etc/systemd/system/ping_daemon.service":         pingUnit,
	"/etc/systemd/system/vpn_mtu_daemon.service":      mtuUnit,
	"/etc/systemd/system/telegram_bot.service":        botUnit,
	"/etc/systemd/system/update_metrics.service":      updateMetricsUnit,
	"/etc/systemd/system/network_load.service":        networkLoadUnit,
	"/etc/systemd/system/home_metrics_daemon.service": homeMetricsUnit,
	"/usr/local/bin/ping_daemon.sh":                   "#!/bin/bash\n",
	"/usr/local/bin/vpn_mtu_daemon.sh":                "#!/bin/bash\n",
	legacyvpn.Sudoers:                                 sudoersScript,
	legacyvpn.BotSudoers:                              sudoersBot,
	legacyvpn.Crontab:                                 crontabStock + cronReboot + "\n" + "  " + cronMinute + "\n",
	legacyvpn.PPPoEPeer:                               peerText,
	legacyvpn.RulesV4:                                 rulesVPN,
	legacyvpn.OpenVPNConf:                             "client\ndev tun0\n",
	legacyvpn.OpenVPNDefault:                          openvpnDefault,
	legacyvpn.WebCrontab:                              webCrontab,
}

var directMode = map[string]string{legacyvpn.RulesV4: rulesDirect}

type unitMap map[string]UnitState

func (m unitMap) fn() func(string) UnitState {
	if m == nil {
		return nil
	}
	return func(u string) UnitState { return m[u] }
}

func (m unitMap) legacy() legacyvpn.UnitState {
	if m == nil {
		return nil
	}
	return func(u string) (bool, bool) { s := m[u]; return s.Enabled, s.Active }
}

func (m unitMap) with(u string, s UnitState) unitMap {
	out := maps.Clone(m)
	out[u] = s
	return out
}

var (
	on      = UnitState{Enabled: true, Active: true}
	flaps   = UnitState{Enabled: true}
	etcOn   = UnitState{Enabled: true, Active: true, FileInEtc: true}
	etcFlap = UnitState{Enabled: true, FileInEtc: true}
)

var standUnits = unitMap{
	"apache2.service":              on,
	"isc-dhcp-server.service":      on,
	"shellinabox.service":          on,
	"cron.service":                 on,
	"netfilter-persistent.service": {Enabled: true, Active: true},
	"openvpn@client1.service":      on,
	"openvpn.service":              {Enabled: true},
	"ping_daemon.service":          etcOn,
	"vpn_mtu_daemon.service":       etcOn,
	"telegram_bot.service":         etcFlap,
	"update_metrics.service":       etcOn,
	"network_load.service":         etcOn,
	"home_metrics_daemon.service":  etcOn,
}

func with(parts ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, p := range parts {
		maps.Copy(out, p)
	}
	return out
}

func build(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if p[len(p)-1] == '/' {
			if err := os.MkdirAll(full, 0o755); err != nil { //nolint:gosec
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func legacyEnv(root string, units unitMap) Env {
	r := legacyvpn.Detect(root, units.legacy())
	return Env{
		Root: root, Units: units.fn(), UnitsKnown: units != nil,
		Legacy: r, LegacyGateway: r.Gateway,
		PlanCards:  []string{"ens2", "ens3"},
		CardMACs:   map[string]string{"ens2": "52:54:00:aa:00:02", "ens3": "52:54:00:aa:00:03"},
		OwnNetplan: ownNetplan,
	}
}

func ids(p Plan) []string {
	out := make([]string, 0, len(p.Items))
	for _, it := range p.Items {
		out = append(out, it.ID)
	}
	return out
}

func find(t *testing.T, p Plan, id string) Item {
	t.Helper()
	for _, it := range p.Items {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("пункта %s нет в плане %v", id, ids(p))
	return Item{}
}
