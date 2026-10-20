package legacyvpn

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type Run struct {
	PID      int
	Changing bool
}

const scriptName = "vpn.sh"

const commLen = 15

var shells = map[string]bool{"bash": true, "sh": true, "dash": true, scriptName: true}

var changers = commSet("apt", "apt-get", "dpkg", "netplan", "iptables", "iptables-restore",
	"ip6tables", "netfilter-persistent", "systemctl", "sysctl", "pon", "poff", "pppd")

var movers = commSet("cp", "mv")

func Running(root string) (Run, bool) {
	procDir := filepath.Join(root, "proc")
	ents, err := os.ReadDir(procDir)
	if err != nil {
		return Run{}, false
	}
	procs := map[int]proc{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if p, ok := readProc(filepath.Join(procDir, e.Name())); ok {
			procs[pid] = p
		}
	}
	return findRun(procs)
}

type proc struct {
	ppid   int
	comm   string
	script bool
}

func readProc(dir string) (proc, bool) {
	status, err := os.ReadFile(filepath.Join(dir, "status")) //nolint:gosec
	if err != nil {
		return proc{}, false
	}
	var p proc
	haveName, havePPid := false, false
	for _, line := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			p.comm, haveName = v, true
		case "PPid":
			if n, err := strconv.Atoi(v); err == nil {
				p.ppid, havePPid = n, true
			}
		}
	}
	if !haveName || !havePPid {
		return proc{}, false
	}
	if shells[p.comm] {
		cmdline, _ := os.ReadFile(filepath.Join(dir, "cmdline")) //nolint:gosec
		p.script = runsScript(cmdline)
	}
	return p, true
}

func runsScript(cmdline []byte) bool {
	for _, arg := range strings.Split(string(cmdline), "\x00") {
		if arg != "" && filepath.Base(arg) == scriptName {
			return true
		}
	}
	return false
}

func findRun(procs map[int]proc) (Run, bool) {
	children := map[int][]int{}
	var tops []int
	for pid, p := range procs {
		children[p.ppid] = append(children[p.ppid], pid)
		if p.script && !procs[p.ppid].script {
			tops = append(tops, pid)
		}
	}
	if len(tops) == 0 {
		return Run{}, false
	}
	slices.Sort(tops)
	for _, top := range tops {
		if changing(procs, children, top) {
			return Run{PID: top, Changing: true}, true
		}
	}
	return Run{PID: tops[0]}, true
}

func changing(procs map[int]proc, children map[int][]int, top int) bool {
	seen := map[int]bool{top: true}
	queue := slices.Clone(children[top])
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		p := procs[pid]
		c := trimComm(p.comm)
		if changers[c] || (movers[c] && procs[p.ppid].script) {
			return true
		}
		queue = append(queue, children[pid]...)
	}
	return false
}

func commSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[trimComm(n)] = true
	}
	return m
}

func trimComm(s string) string {
	if len(s) > commLen {
		return s[:commLen]
	}
	return s
}
