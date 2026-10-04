package sysinfo

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CPU struct {
	Model   string
	Cores   int
	Threads int

	CryptoFast bool
}

type Disk struct {
	Name  string
	Model string
	Bytes uint64

	Kind string
}

type Machine struct {
	CPU      CPU
	MemBytes uint64
	Disks    []Disk
	OSName   string
	Kernel   string
}

type Boot struct {
	Since time.Time
	For   time.Duration
}

type Port struct {
	Name   string
	Driver string

	SpeedMbit  int
	Duplex     string
	SpeedKnown bool
}

var Root = "/"

var (
	once    sync.Once
	machine Machine
)

func Read() Machine {
	once.Do(func() { machine = read() })
	return machine
}

func read() Machine {
	var m Machine
	if raw, err := os.ReadFile(filepath.Join(Root, "proc/cpuinfo")); err == nil {
		m.CPU = ParseCPU(raw)
	}
	if raw, err := os.ReadFile(filepath.Join(Root, "proc/meminfo")); err == nil {
		m.MemBytes = ParseMemTotal(raw)
	}
	if raw, err := os.ReadFile(filepath.Join(Root, "etc/os-release")); err == nil {
		m.OSName = ParseOSName(raw)
	}
	if raw, err := os.ReadFile(filepath.Join(Root, "proc/sys/kernel/osrelease")); err == nil {
		m.Kernel = strings.TrimSpace(string(raw))
	}
	m.Disks = disks()
	return m
}

func ParseCPU(raw []byte) CPU {
	var c CPU
	seen := map[string]bool{}
	var pkg, core string
	flush := func() {
		if core != "" {
			seen[pkg+"/"+core] = true
		}
		pkg, core = "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "processor":
			c.Threads++
		case "model name":
			if c.Model == "" {
				c.Model = val
			}
		case "physical id":
			pkg = val
		case "core id":
			core = val
		case "flags", "Features":

			for _, f := range strings.Fields(val) {
				if f == "aes" || f == "vaes" {
					c.CryptoFast = true
				}
			}
		}
	}
	flush()
	c.Cores = len(seen)
	return c
}

func ParseMemTotal(raw []byte) uint64 {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(key) != "MemTotal" {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func ParseOSName(raw []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if ok && key == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(val), `"`)
		}
	}
	return ""
}

func ParseUptime(raw []byte, now time.Time) (Boot, bool) {
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return Boot{}, false
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 {
		return Boot{}, false
	}
	d := time.Duration(secs * float64(time.Second))
	return Boot{Since: now.Add(-d), For: d}, true
}

func Uptime() (Boot, bool) {
	raw, err := os.ReadFile(filepath.Join(Root, "proc/uptime"))
	if err != nil {
		return Boot{}, false
	}
	return ParseUptime(raw, time.Now())
}

func ParseBootID(raw []byte) (string, bool) {
	id := strings.TrimSpace(string(raw))
	if len(id) != 36 {
		return "", false
	}
	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "", false
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
		default:
			return "", false
		}
	}
	return id, true
}

func BootID() (string, bool) {
	raw, err := os.ReadFile(filepath.Join(Root, "proc/sys/kernel/random/boot_id"))
	if err != nil {
		return "", false
	}
	return ParseBootID(raw)
}

var skipBlock = []string{"loop", "ram", "sr", "dm-", "zram", "md"}

func disks() []Disk {
	dir := filepath.Join(Root, "sys/block")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Disk
	for _, e := range entries {
		name := e.Name()
		skip := false
		for _, p := range skipBlock {
			if strings.HasPrefix(name, p) {
				skip = true
			}
		}
		if skip {
			continue
		}
		d := Disk{Name: name}
		if raw, err := os.ReadFile(filepath.Join(dir, name, "size")); err == nil { //nolint:gosec
			if sectors, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {

				d.Bytes = sectors * 512
			}
		}
		d.Model = strings.TrimSpace(readFile(filepath.Join(dir, name, "device", "model")))
		d.Kind = diskKind(name, strings.TrimSpace(readFile(filepath.Join(dir, name, "queue", "rotational"))), d.Model)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func diskKind(name, rotational, model string) string {
	switch {
	case strings.HasPrefix(name, "nvme"):
		return "NVMe"
	case strings.HasPrefix(name, "vd") || model == "":
		return ""
	case rotational == "0":
		return "SSD"
	case rotational == "1":
		return "жёсткий диск"
	}
	return ""
}

func Ports(names []string) []Port {
	out := make([]Port, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		base := filepath.Join(Root, "sys/class/net", n)
		p := Port{Name: n}
		p.Duplex = strings.TrimSpace(readFile(filepath.Join(base, "duplex")))
		if p.Duplex == "unknown" {
			p.Duplex = ""
		}
		if link, err := os.Readlink(filepath.Join(base, "device", "driver")); err == nil {
			p.Driver = filepath.Base(link)
		}
		if v, err := strconv.Atoi(strings.TrimSpace(readFile(filepath.Join(base, "speed")))); err == nil && v > 0 {
			p.SpeedMbit, p.SpeedKnown = v, true
		}
		out = append(out, p)
	}
	return out
}

func readFile(path string) string {
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return ""
	}
	return string(raw)
}
