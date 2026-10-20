package main

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
)

const (
	askDir           = "/run/systemd/ask-password"
	plymouthDefaults = "/usr/share/plymouth/plymouthd.defaults"
	plymouthConf     = "/etc/plymouth/plymouthd.conf"

	askPoll = 200 * time.Millisecond
)

func runDiskUnlock() int {
	switch mode := splashMode(); mode {
	case splashDraws:
		log.Print("disk-unlock: заставка рисует — штатный экран пароля")
		return 0
	case splashText:
		log.Print("disk-unlock: заставка жива, но печатает текст — закрываем её")
		quitSplash()
	default:
		log.Print("disk-unlock: заставки нет")
	}
	consoles, restore := openTextConsoles()
	defer restore()
	if len(consoles) == 0 {
		log.Print("disk-unlock: ни одной консоли не открыть")
		return 1
	}
	log.Printf("disk-unlock: диалог на консолях: %s", consoles.names())
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; close(stop) }()
	a := &askAgent{dir: askDir, consoles: consoles, done: map[string]bool{}, answered: map[string]bool{}}
	a.serve(stop)
	return 0
}

type splash int

const (
	splashNone splash = iota
	splashText
	splashDraws
)

func splashMode() splash {
	if _, err := os.Stat(plymouthPIDFile); err != nil {
		return splashNone
	}
	ply, err := findBinary([]string{"/usr/bin/plymouth", "/bin/plymouth"})
	if err != nil || exec.Command(ply, "--ping").Run() != nil { //nolint:gosec
		return splashText
	}
	deadline := time.Now().Add(splashDeviceWait())
	for {
		if plymouthDraws(plymouthPIDFile) {
			return splashDraws
		}
		if time.Now().After(deadline) {
			return splashText
		}
		time.Sleep(askPoll)
	}
}

func splashDeviceWait() time.Duration {
	for _, path := range []string{plymouthConf, plymouthDefaults} {
		if d, ok := plymouthSetting(path, "DeviceTimeout"); ok {
			return d
		}
	}
	return 0
}

func plymouthSetting(path, key string) (time.Duration, bool) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		sec, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || sec < 0 {
			return 0, false
		}
		return time.Duration(sec * float64(time.Second)), true
	}
	return 0, false
}

func quitSplash() {
	raw, _ := os.ReadFile(plymouthPIDFile)
	if ply, err := findBinary([]string{"/usr/bin/plymouth", "/bin/plymouth"}); err == nil {
		_ = exec.Command(ply, "quit").Run() //nolint:gosec
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {

		proc := "/proc/" + strconv.Itoa(pid)
		deadline := time.Now().Add(consoleTakeover)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(proc); err != nil { //nolint:gosec
				break
			}
			time.Sleep(consoleTakeoverPoll)
		}
		if _, err := os.Stat(proc); err != nil { //nolint:gosec
			_ = os.Remove(plymouthPIDFile)
		}
	}
	if sc, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
		_ = exec.Command(sc, "stop", "--no-block", "systemd-ask-password-plymouth.path", //nolint:gosec
			"systemd-ask-password-plymouth.service").Run()
	}
}

type askRequest struct {
	path, socket, message, id string
	pid                       int
	notAfter                  uint64
}

func parseAsk(data []byte) (askRequest, error) {
	var r askRequest
	in := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			in = line == "[Ask]"
		case in:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "Socket":
				r.socket = v
			case "Message":
				r.message = v
			case "Id":
				r.id = v
			case "PID":
				r.pid, _ = strconv.Atoi(v)
			case "NotAfter":
				r.notAfter, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	if r.socket == "" {
		return r, errors.New("в запросе нет сокета ответа")
	}
	return r, nil
}

func (r askRequest) alive(now uint64) bool {
	if r.pid > 0 {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(r.pid))); err != nil {
			return false
		}
	}
	return r.notAfter == 0 || now < r.notAfter
}

func (r askRequest) deadline(now uint64) time.Time {
	if r.notAfter == 0 || r.notAfter <= now {
		return time.Time{}
	}
	left := r.notAfter - now
	if left > math.MaxInt64/uint64(time.Microsecond) {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(left) * time.Microsecond) //nolint:gosec
}

func (r askRequest) isDisk() bool { return strings.HasPrefix(r.id, "cryptsetup:") }

func monotonicNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e6 + uint64(ts.Nsec)/1e3 //nolint:gosec
}

func answerPacket(secret []byte) []byte {
	p := make([]byte, 0, len(secret)+2)
	p = append(p, '+')
	p = append(p, secret...)
	return append(p, 0)
}

func answer(socket string, secret []byte) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck
	p := answerPacket(secret)
	defer wipeBytes(p)
	return unix.Sendto(fd, p, unix.MSG_NOSIGNAL, &unix.SockaddrUnix{Name: socket})
}

type askAgent struct {
	dir      string
	consoles textConsoles

	done map[string]bool

	answered map[string]bool
}

func (a *askAgent) pending() []askRequest {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil
	}
	now := monotonicNow()
	seen := map[string]bool{}
	var out []askRequest
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "ask.") || e.IsDir() {
			continue
		}
		path := filepath.Join(a.dir, e.Name())
		seen[path] = true
		if a.done[path] {
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			continue
		}
		r, err := parseAsk(data)
		if err != nil || !r.alive(now) {
			continue
		}
		r.path = path
		out = append(out, r)
	}
	for path := range a.done {
		if !seen[path] {
			delete(a.done, path)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func (a *askAgent) serve(stop <-chan struct{}) {
	for {
		reqs := a.pending()
		if len(reqs) == 0 {
			select {
			case <-stop:
				return
			case <-time.After(askPoll):
			}
			continue
		}
		if !a.handle(reqs[0], stop) {
			return
		}
	}
}

func (a *askAgent) handle(r askRequest, stop <-chan struct{}) bool {
	var lines []textLine
	label := r.message
	if r.isDisk() {
		label = diskcrypt.Text("vp:unlock")
		if a.answered[r.id] {
			lines = append(lines, textLine{diskcrypt.Text("vp:wrong"), styleError})
		}
	}
	a.consoles.draw(lines, label)

	gone := make(chan struct{})
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		for {
			select {
			case <-quit:
				return
			case <-stop:
				close(gone)
				return
			case <-time.After(askPoll):
				if _, err := os.Stat(r.path); err != nil {
					close(gone)
					return
				}
			}
		}
	}()
	secret, err := a.consoles.ask(r.deadline(monotonicNow()), gone)
	defer wipeBytes(secret)
	select {
	case <-stop:
		return false
	default:
	}
	if err != nil {
		log.Printf("disk-unlock: ввод прерван: %v", err)
		a.done[r.path] = true
		return true
	}
	if err := answer(r.socket, secret); err != nil {
		log.Printf("disk-unlock: ответ не доставлен: %v", err)
		return true
	}
	a.done[r.path] = true
	if r.isDisk() {
		a.answered[r.id] = true
	}
	return true
}
