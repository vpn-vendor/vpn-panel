package sockowner

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type Socket struct {
	Proto string

	Addr  netip.Addr
	Port  int
	Inode uint64
	V6    bool
}

type Owner struct {
	PID  int
	Comm string
	Unit string
}

const (
	stateListen = 0x0A
	stateClose  = 0x07
)

var hostOrder binary.ByteOrder = binary.NativeEndian

func List(root, proto string, port int) ([]Socket, error) {
	var want uint64
	switch proto {
	case "tcp":
		want = stateListen
	case "udp":
		want = stateClose
	default:
		return nil, fmt.Errorf("протокол %q не поддерживается", proto)
	}
	if port < 1 || port > 0xFFFF {
		return nil, fmt.Errorf("порт %d вне диапазона", port)
	}
	dir := filepath.Join(root, "proc", "net")
	out, err := readTable(filepath.Join(dir, proto), proto, false, port, want)
	if err != nil {
		return nil, err
	}
	v6, err := readTable(filepath.Join(dir, proto+"6"), proto, true, port, want)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return append(out, v6...), nil
}

func readTable(name, proto string, v6 bool, port int, state uint64) ([]Socket, error) {
	f, err := os.Open(name) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []Socket
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		fields := strings.Fields(sc.Text())
		if n == 1 {

			if len(fields) == 0 || fields[0] != "sl" {
				return nil, fmt.Errorf("%s: нет шапки таблицы", name)
			}
			continue
		}
		if len(fields) == 0 {
			continue
		}
		s, match, err := parseLine(fields, v6, port, state)
		if err != nil {
			return nil, fmt.Errorf("%s, строка %d: %w", name, n, err)
		}
		if !match {
			continue
		}
		s.Proto = proto
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: пустая таблица", name)
	}
	return out, nil
}

func parseLine(f []string, v6 bool, port int, state uint64) (Socket, bool, error) {

	if len(f) < 10 {
		return Socket{}, false, errors.New("мало полей")
	}
	hexAddr, hexPort, ok := strings.Cut(f[1], ":")
	if !ok || len(hexPort) != 4 {
		return Socket{}, false, fmt.Errorf("адрес %q", f[1])
	}
	p, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return Socket{}, false, fmt.Errorf("порт %q", hexPort)
	}
	if len(f[3]) != 2 {
		return Socket{}, false, fmt.Errorf("состояние %q", f[3])
	}
	st, err := strconv.ParseUint(f[3], 16, 8)
	if err != nil {
		return Socket{}, false, fmt.Errorf("состояние %q", f[3])
	}
	if int(p) != port || st != state {
		return Socket{}, false, nil
	}
	addr, err := parseAddr(hexAddr, v6)
	if err != nil {
		return Socket{}, false, err
	}
	inode, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return Socket{}, false, fmt.Errorf("inode %q", f[9])
	}
	return Socket{Addr: addr, Port: port, Inode: inode, V6: v6}, true, nil
}

func parseAddr(s string, v6 bool) (netip.Addr, error) {
	words := 1
	if v6 {
		words = 4
	}
	if len(s) != words*8 {
		return netip.Addr{}, fmt.Errorf("адрес %q", s)
	}
	var b [16]byte
	for i := range words {
		w, err := strconv.ParseUint(s[i*8:i*8+8], 16, 32)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("адрес %q", s)
		}
		hostOrder.PutUint32(b[i*4:], uint32(w))
	}
	if !v6 {
		return netip.AddrFrom4([4]byte(b[:4])), nil
	}
	return netip.AddrFrom16(b).Unmap(), nil
}

func Owners(root string, inodes []uint64) (map[uint64]Owner, error) {
	out := make(map[uint64]Owner, len(inodes))
	want := make(map[uint64]bool, len(inodes))
	for _, ino := range inodes {
		want[ino] = true
	}
	if len(want) == 0 {
		return out, nil
	}
	procDir := filepath.Join(root, "proc")
	names, err := readNames(procDir)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(names))
	for _, name := range names {
		if pid, err := strconv.ParseUint(name, 10, 31); err == nil && pid > 0 {
			pids = append(pids, int(pid))
		}
	}

	slices.Sort(pids)

	var firstErr error
	unread := 0
	for _, pid := range pids {
		if len(out) == len(want) {
			break
		}
		dir := filepath.Join(procDir, strconv.Itoa(pid))
		held, err := heldSockets(filepath.Join(dir, "fd"), want, out)
		if err == nil && len(held) > 0 {
			var o Owner
			o, err = ownerOf(dir, pid)
			if err == nil {
				for _, ino := range held {
					out[ino] = o
				}
			}
		}
		if err != nil && !vanished(err) {
			unread++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if len(out) < len(want) && firstErr != nil {
		return out, fmt.Errorf("не прочитано процессов: %d: %w", unread, firstErr)
	}
	return out, nil
}

func heldSockets(fdDir string, want map[uint64]bool, found map[uint64]Owner) ([]uint64, error) {
	fds, err := readNames(fdDir)
	if err != nil {
		return nil, err
	}
	var held []uint64
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd))
		if err != nil {
			if vanished(err) {
				continue
			}
			return nil, err
		}
		ino, ok := socketInode(link)
		if !ok || !want[ino] || slices.Contains(held, ino) {
			continue
		}
		if _, done := found[ino]; done {
			continue
		}
		held = append(held, ino)
	}
	return held, nil
}

func ownerOf(dir string, pid int) (Owner, error) {
	comm, err := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec
	if err != nil {
		return Owner{}, err
	}
	cg, err := os.ReadFile(filepath.Join(dir, "cgroup")) //nolint:gosec
	if err != nil {
		return Owner{}, err
	}
	return Owner{PID: pid, Comm: strings.TrimSuffix(string(comm), "\n"), Unit: UnitOf(cg)}, nil
}

func socketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return 0, false
	}
	ino, err := strconv.ParseUint(s, 10, 64)
	return ino, err == nil
}

func readNames(dir string) ([]string, error) {
	f, err := os.Open(dir) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Readdirnames(-1)
}

func vanished(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func UnitOf(cgroup []byte) string {
	p, ok := unifiedPath(cgroup)
	if !ok {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	i := 0
	for i < len(parts) && strings.HasSuffix(parts[i], ".slice") {
		i++
	}
	if i == len(parts) || parts[0] == "user.slice" {
		return ""
	}
	unit := parts[i]
	if !validUnit(unit) {
		return ""
	}

	if strings.HasPrefix(unit, "user@") || (strings.HasPrefix(unit, "session-") && strings.HasSuffix(unit, ".scope")) {
		return ""
	}
	return unit
}

func unifiedPath(data []byte) (string, bool) {
	for line := range strings.Lines(string(data)) {
		p, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "0::")
		if !ok {
			continue
		}
		p = strings.TrimSuffix(p, " (deleted)")

		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return "", false
		}
		return path.Clean(p), true
	}
	return "", false
}

func validUnit(u string) bool {
	base, ok := strings.CutSuffix(u, ".service")
	if !ok {
		base, ok = strings.CutSuffix(u, ".scope")
	}
	if !ok || base == "" {
		return false
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune(":-_.\\@", c):
		default:
			return false
		}
	}
	return true
}
