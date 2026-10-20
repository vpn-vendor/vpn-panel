package legacyvpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeProc struct {
	pid, ppid int
	comm      string
	argv      []string
}

func procRoot(t *testing.T, ps []fakeProc) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range ps {
		dir := filepath.Join(root, "proc", fmt.Sprint(p.pid))
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		status := fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\n",
			p.comm, p.pid, p.pid, p.ppid)
		cmdline := ""
		if len(p.argv) > 0 {
			cmdline = strings.Join(p.argv, "\x00") + "\x00"
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o444); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o444); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	for _, name := range []string{"self", "sys"} {
		if err := os.MkdirAll(filepath.Join(root, "proc", name), 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	return root
}

var background = []fakeProc{
	{pid: 1, ppid: 0, comm: "systemd", argv: []string{"/sbin/init"}},
	{pid: 2, ppid: 0, comm: "kthreadd"},
	{pid: 410, ppid: 1, comm: "ping_daemon.sh", argv: []string{"/bin/bash", "/usr/local/bin/ping_daemon.sh"}},
	{pid: 411, ppid: 410, comm: "ping", argv: []string{"ping", "-c", "1", "8.8.8.8"}},
	{pid: 420, ppid: 1, comm: "vpn_mtu_daemon.", argv: []string{"/bin/bash", "/usr/local/bin/vpn_mtu_daemon.sh"}},
	{pid: 421, ppid: 420, comm: "iptables", argv: []string{"iptables", "-C", "FORWARD"}},
	{pid: 500, ppid: 1, comm: "sshd", argv: []string{"sshd: admin [priv]"}},
	{pid: 510, ppid: 500, comm: "bash", argv: []string{"-bash"}},
}

func TestRunning(t *testing.T) {
	tests := []struct {
		name  string
		procs []fakeProc
		want  Run
		found bool
	}{
		{name: "только демоны старого шлюза"},
		{
			name: "скрипт ждёт ответа в меню",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
			},
			want: Run{PID: 600}, found: true,
		},
		{
			name: "sudo bash ./vpn.sh, apt-get ставит пакеты",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "sudo", argv: []string{"sudo", "bash", "./vpn.sh"}},
				{pid: 601, ppid: 600, comm: "sudo", argv: []string{"sudo", "bash", "./vpn.sh"}},
				{pid: 602, ppid: 601, comm: "bash", argv: []string{"bash", "./vpn.sh"}},
				{pid: 603, ppid: 602, comm: "apt-get", argv: []string{"apt-get", "install", "-y", "openvpn"}},
			},
			want: Run{PID: 602, Changing: true}, found: true,
		},
		{
			name: "запуск ./vpn.sh: dpkg под apt-get в подоболочке",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "vpn.sh", argv: []string{"/bin/bash", "/root/vpn.sh"}},
				{pid: 601, ppid: 600, comm: "vpn.sh", argv: []string{"/bin/bash", "/root/vpn.sh"}},
				{pid: 602, ppid: 601, comm: "apt-get", argv: []string{"apt-get", "upgrade", "-y"}},
				{pid: 603, ppid: 602, comm: "dpkg", argv: []string{"/usr/bin/dpkg", "--configure", "-a"}},
			},
			want: Run{PID: 600, Changing: true}, found: true,
		},
		{
			name: "netplan apply",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "/root/vpn.sh"}},
				{pid: 601, ppid: 600, comm: "netplan", argv: []string{"/usr/bin/python3", "/usr/sbin/netplan", "apply"}},
			},
			want: Run{PID: 600, Changing: true}, found: true,
		},
		{
			name: "iptables-restore с обрезанным comm",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 601, ppid: 600, comm: "iptables-restor", argv: []string{"iptables-restore"}},
			},
			want: Run{PID: 600, Changing: true}, found: true,
		},
		{
			name: "mv файлов Netplan самим скриптом",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 601, ppid: 600, comm: "mv", argv: []string{"mv", "/etc/netplan/50-cloud-init.yaml", "/etc/netplan/backup_2026-10-19_133534/"}},
			},
			want: Run{PID: 600, Changing: true}, found: true,
		},
		{
			name: "cp внутри pip не считается",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 601, ppid: 600, comm: "pip", argv: []string{"/var/www/html/bot_source/venv/bin/python", "pip", "install"}},
				{pid: 602, ppid: 601, comm: "cp", argv: []string{"cp", "a", "b"}},
			},
			want: Run{PID: 600}, found: true,
		},
		{
			name: "скрипт ждёт PPPoE в sleep",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 601, ppid: 600, comm: "sleep", argv: []string{"sleep", "1"}},
			},
			want: Run{PID: 600}, found: true,
		},
		{
			name: "номер подоболочки меньше после переполнения счётчика",
			procs: []fakeProc{
				{pid: 900, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 300, ppid: 900, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 301, ppid: 300, comm: "sysctl", argv: []string{"sysctl", "-p"}},
			},
			want: Run{PID: 900, Changing: true}, found: true,
		},
		{
			name: "два запуска: важнее тот, что меняет систему",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh"}},
				{pid: 700, ppid: 510, comm: "bash", argv: []string{"bash", "/root/vpn.sh"}},
				{pid: 701, ppid: 700, comm: "systemctl", argv: []string{"systemctl", "restart", "isc-dhcp-server"}},
			},
			want: Run{PID: 700, Changing: true}, found: true,
		},
		{
			name: "редактор и загрузка с vpn.sh в аргументах",
			procs: []fakeProc{
				{pid: 600, ppid: 510, comm: "nano", argv: []string{"nano", "vpn.sh"}},
				{pid: 601, ppid: 510, comm: "wget", argv: []string{"wget", "-O", "vpn.sh"}},
				{pid: 602, ppid: 510, comm: "bash", argv: []string{"bash", "-c", "less vpn.sh"}},
				{pid: 603, ppid: 510, comm: "bash", argv: []string{"bash", "vpn.sh.1"}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := procRoot(t, append(append([]fakeProc{}, background...), tc.procs...))
			got, ok := Running(root)
			if ok != tc.found || got != tc.want {
				t.Fatalf("получено %+v %v, ожидали %+v %v", got, ok, tc.want, tc.found)
			}
		})
	}
}

func TestRunningWithoutProc(t *testing.T) {
	if _, ok := Running(t.TempDir()); ok {
		t.Fatal("без /proc найден запуск")
	}
}
