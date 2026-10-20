package sockowner

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	hostOrder = binary.LittleEndian
	os.Exit(m.Run())
}

const (
	tcpHead  = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	tcp6Head = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	udpHead  = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"

	apacheV6 = "   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19849 1 0000000000000000 100 0 0 10 0"

	apacheV4 = "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19849 1 0000000000000000 100 0 0 10 0"

	estab = "   2: 010BA8C0:0050 640BA8C0:C350 01 00000000:00000000 02:000AFC80 00000000    33        0 31337 2 0000000000000000 20 4 30 10 -1"
	sshd  = "   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20123 1 0000000000000000 100 0 0 10 0"

	mapped = "   4: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40001 1 0000000000000000 100 0 0 10 0"

	linkLocal = "   5: 000080FE000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40002 1 0000000000000000 100 0 0 10 0"

	dhcpd = "  12: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 21311 2 0000000000000000 0"

	kea = "  15: 010BA8C0:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 23874 2 0000000000000000 0"

	dhclient  = "  16: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 23900 2 0000000000000000 0"
	udpConn67 = "  17: 010BA8C0:0043 640BA8C0:0044 01 00000000:00000000 00:00000000 00000000     0        0 23901 2 0000000000000000 0"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
}

func table(head string, lines ...string) string {
	return head + "\n" + strings.Join(lines, "\n") + "\n"
}

func TestList(t *testing.T) {
	any4 := netip.IPv4Unspecified()
	any6 := netip.IPv6Unspecified()
	cases := []struct {
		name  string
		files map[string]string
		proto string
		port  int
		want  []Socket
		err   bool
	}{
		{
			name: "Apache двойного стека только в tcp6",
			files: map[string]string{
				"proc/net/tcp":  table(tcpHead, sshd),
				"proc/net/tcp6": table(tcp6Head, apacheV6),
			},
			proto: "tcp", port: 80,
			want: []Socket{{Proto: "tcp", Addr: any6, Port: 80, Inode: 19849, V6: true}},
		},
		{
			name: "Apache после перезагрузки только в tcp, соединение не берётся",
			files: map[string]string{
				"proc/net/tcp":  table(tcpHead, apacheV4, estab, sshd),
				"proc/net/tcp6": table(tcp6Head),
			},
			proto: "tcp", port: 80,
			want: []Socket{{Proto: "tcp", Addr: any4, Port: 80, Inode: 19849}},
		},
		{
			name: "IPv4-mapped и link-local в tcp6",
			files: map[string]string{
				"proc/net/tcp":  table(tcpHead),
				"proc/net/tcp6": table(tcp6Head, mapped, linkLocal),
			},
			proto: "tcp", port: 80,
			want: []Socket{
				{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 80, Inode: 40001, V6: true},
				{Proto: "tcp", Addr: netip.MustParseAddr("fe80::1"), Port: 80, Inode: 40002, V6: true},
			},
		},
		{
			name: "dhcpd и Kea на 67, таблицы udp6 нет",
			files: map[string]string{
				"proc/net/udp": table(udpHead, dhcpd, kea, dhclient, udpConn67),
			},
			proto: "udp", port: 67,
			want: []Socket{
				{Proto: "udp", Addr: any4, Port: 67, Inode: 21311},
				{Proto: "udp", Addr: netip.MustParseAddr("192.168.11.1"), Port: 67, Inode: 23874},
			},
		},
		{
			name: "порт свободен",
			files: map[string]string{
				"proc/net/tcp":  table(tcpHead, sshd, estab),
				"proc/net/tcp6": table(tcp6Head),
			},
			proto: "tcp", port: 443,
		},
		{
			name:  "нет таблицы IPv4",
			files: map[string]string{"proc/net/tcp6": table(tcp6Head, apacheV6)},
			proto: "tcp", port: 80, err: true,
		},
		{
			name:  "нет шапки",
			files: map[string]string{"proc/net/tcp": apacheV4 + "\n"},
			proto: "tcp", port: 80, err: true,
		},
		{
			name:  "пустая таблица",
			files: map[string]string{"proc/net/tcp": ""},
			proto: "tcp", port: 80, err: true,
		},
		{
			name: "сломанный порт в чужой строке",
			files: map[string]string{
				"proc/net/tcp": table(tcpHead, apacheV4, "   9: 00000000:00ZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0"),
			},
			proto: "tcp", port: 80, err: true,
		},
		{
			name: "адрес IPv6 в таблице IPv4",
			files: map[string]string{
				"proc/net/tcp": table(tcpHead, strings.Replace(apacheV6, "   1:", "   0:", 1)),
			},
			proto: "tcp", port: 80, err: true,
		},
		{
			name: "сломанная таблица IPv6",
			files: map[string]string{
				"proc/net/tcp":  table(tcpHead, apacheV4),
				"proc/net/tcp6": table(tcp6Head, "   1: 0000:0050 0A"),
			},
			proto: "tcp", port: 80, err: true,
		},
		{
			name:  "неизвестный протокол",
			files: map[string]string{"proc/net/tcp": table(tcpHead)},
			proto: "sctp", port: 80, err: true,
		},
		{
			name:  "порт 0",
			files: map[string]string{"proc/net/tcp": table(tcpHead)},
			proto: "tcp", port: 0, err: true,
		},
		{
			name:  "порт больше 65535",
			files: map[string]string{"proc/net/tcp": table(tcpHead)},
			proto: "tcp", port: 65536, err: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeFiles(t, root, c.files)
			got, err := List(root, c.proto, c.port)
			if c.err {
				if err == nil {
					t.Fatalf("ожидалась ошибка, получено %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("получено %+v\nожидалось %+v", got, c.want)
			}
		})
	}
}

type proc struct {
	comm, cgroup string
	fds          map[string]string
	noFdDir      bool
	lockedFdDir  bool
}

func buildProc(t *testing.T, root string, procs map[string]proc) {
	t.Helper()
	writeFiles(t, root, map[string]string{"proc/net/tcp": table(tcpHead)})
	if err := os.Symlink("4021", filepath.Join(root, "proc", "self")); err != nil {
		t.Fatal(err)
	}
	for pid, p := range procs {
		dir := filepath.Join(root, "proc", pid)
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		if p.comm != "" {
			writeFiles(t, dir, map[string]string{"comm": p.comm})
		}
		if p.cgroup != "" {
			writeFiles(t, dir, map[string]string{"cgroup": p.cgroup})
		}
		if p.noFdDir {
			continue
		}
		fdDir := filepath.Join(dir, "fd")
		if err := os.Mkdir(fdDir, 0o755); err != nil { //nolint:gosec
			t.Fatal(err)
		}
		for fd, target := range p.fds {
			if err := os.Symlink(target, filepath.Join(fdDir, fd)); err != nil {
				t.Fatal(err)
			}
		}
		if p.lockedFdDir {
			if err := os.Chmod(fdDir, 0); err != nil { //nolint:gosec
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) }) //nolint:gosec
		}
	}
}

func TestOwners(t *testing.T) {
	apache := "0::/system.slice/apache2.service\n"
	base := map[string]proc{

		"815": {comm: "apache2\n", cgroup: apache, fds: map[string]string{"3": "socket:[19849]", "4": "pipe:[1234]"}},
		"812": {comm: "apache2\n", cgroup: apache, fds: map[string]string{
			"0": "/dev/null", "3": "socket:[19849]", "5": "anon_inode:[eventfd]", "6": "socket:[19850]",
		}},
		"1290": {comm: "dhcpd\n", cgroup: "0::/system.slice/isc-dhcp-server.service\n", fds: map[string]string{"7": "socket:[21311]"}},
		"4021": {comm: "python3\n", cgroup: "0::/user.slice/user-1000.slice/session-4.scope\n", fds: map[string]string{"3": "socket:[30001]"}},

		"700": {fds: map[string]string{"3": "socket:[19849]"}},

		"701": {noFdDir: true},

		"2": {comm: "kthreadd\n", cgroup: "0::/\n"},
	}
	cases := []struct {
		name   string
		procs  map[string]proc
		inodes []uint64
		want   map[uint64]Owner
	}{
		{
			name:   "Apache, dhcpd, сеанс входа",
			procs:  base,
			inodes: []uint64{19849, 21311, 30001},
			want: map[uint64]Owner{
				19849: {PID: 812, Comm: "apache2", Unit: "apache2.service"},
				21311: {PID: 1290, Comm: "dhcpd", Unit: "isc-dhcp-server.service"},
				30001: {PID: 4021, Comm: "python3", Unit: ""},
			},
		},
		{
			name:   "сокет без держателя не попадает в ответ",
			procs:  base,
			inodes: []uint64{21311, 99999},
			want:   map[uint64]Owner{21311: {PID: 1290, Comm: "dhcpd", Unit: "isc-dhcp-server.service"}},
		},
		{
			name:   "пустой запрос",
			procs:  base,
			inodes: nil,
			want:   map[uint64]Owner{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			buildProc(t, root, c.procs)
			got, err := Owners(root, c.inodes)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("получено %+v\nожидалось %+v", got, c.want)
			}
		})
	}
}

func TestOwnersUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root читает каталог и без прав")
	}
	procs := map[string]proc{
		"1290": {comm: "dhcpd\n", cgroup: "0::/system.slice/isc-dhcp-server.service\n", fds: map[string]string{"7": "socket:[21311]"}},
		"1000": {comm: "unknown\n", cgroup: "0::/system.slice/x.service\n", lockedFdDir: true},
	}
	dhcpd := Owner{PID: 1290, Comm: "dhcpd", Unit: "isc-dhcp-server.service"}
	cases := []struct {
		name   string
		inodes []uint64
		want   map[uint64]Owner
		err    bool
	}{
		{name: "все найдены", inodes: []uint64{21311}, want: map[uint64]Owner{21311: dhcpd}},
		{name: "не найден", inodes: []uint64{21311, 19849}, want: map[uint64]Owner{21311: dhcpd}, err: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			buildProc(t, root, procs)
			got, err := Owners(root, c.inodes)
			if (err != nil) != c.err {
				t.Fatalf("ошибка %v, ожидалась %v", err, c.err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("получено %+v\nожидалось %+v", got, c.want)
			}
		})
	}
}

func TestOwnersNoProc(t *testing.T) {
	if _, err := Owners(t.TempDir(), []uint64{1}); err == nil {
		t.Fatal("без /proc обязана быть ошибка")
	}
}

func TestUnitOf(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"0::/system.slice/apache2.service\n", "apache2.service"},
		{"0::/init.scope\n", "init.scope"},
		{"0::/system.slice/system-getty.slice/getty@tty1.service\n", "getty@tty1.service"},
		{"0::/system.slice/docker-0123abcd.scope\n", "docker-0123abcd.scope"},
		{"0::/machine.slice/machine-qemu\\x2d1\\x2dvm.scope\n", "machine-qemu\\x2d1\\x2dvm.scope"},

		{"0::/system.slice/docker.service/x/kea-dhcp4-server.service\n", "docker.service"},
		{"0::/system.slice/apache2.service (deleted)\n", "apache2.service"},
		{"12:pids:/system.slice/apache2.service\n1:name=systemd:/system.slice/apache2.service\n0::/system.slice/apache2.service\n", "apache2.service"},
		{"0::/user.slice/user-1000.slice/session-4.scope\n", ""},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service\n", ""},
		{"0::/system.slice/session-4.scope\n", ""},
		{"0::/\n", ""},
		{"0::/system.slice\n", ""},
		{"0::/system.slice/run-u12.mount\n", ""},
		{"0::/system.slice/.service\n", ""},
		{"0::/system.slice/bad name.service\n", ""},
		{"0::/../../system.slice/kea-dhcp4-server.service\n", ""},
		{"0::relative.service\n", ""},
		{"12:cpu:/system.slice/apache2.service\n", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := UnitOf([]byte(c.in)); got != c.want {
			t.Errorf("%q → %q, ожидалось %q", c.in, got, c.want)
		}
	}
}
