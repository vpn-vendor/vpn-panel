package main

import (
	"errors"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
)

const (
	kdGetKbdLED = 0x4B64
	ledCapsLock = 0x04
)

type textConsole struct {
	dev   string
	f     *os.File
	vt    bool
	cols  int
	line  *starLine
	stuck bool
}

func (c *textConsole) Write(p []byte) (int, error) {
	fd := int(c.f.Fd())
	wait := consoleTakeover
	if c.stuck {
		wait = consoleTick
	}
	deadline := time.Now().Add(wait)
	written := 0
	for written < len(p) {
		n, err := unix.Write(fd, p[written:])
		if n > 0 {
			written += n
		}
		switch {
		case err == nil:
			continue
		case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR):
			if time.Now().After(deadline) {
				if !c.stuck {
					log.Printf("консоль %s: не принимает вывод, дальше без неё", c.dev)
				}
				c.stuck = true
				return len(p), nil
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}} //nolint:gosec
			_, _ = unix.Poll(fds, int(consoleTick.Milliseconds()))
		default:
			return written, err
		}
	}
	c.stuck = false
	return written, nil
}

type textConsoles []*textConsole

func openTextConsoles() (textConsoles, func()) {
	active, _ := os.ReadFile("/sys/class/tty/console/active")
	var out textConsoles
	var restores []func()
	for _, dev := range consoleDevices(string(active)) {

		f, err := os.OpenFile(dev, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0) //nolint:gosec
		if err != nil {
			log.Printf("консоль %s: %v", dev, err)
			continue
		}
		c := &textConsole{dev: dev, f: f, vt: isVirtualTerminal(dev)}
		if c.vt {

			_, _ = io.WriteString(c, "\x1b[H\x1b[2J.\r")
			waitConsoleTakeover()
			font, restoreFont := consoleFontOn(dev, int(f.Fd()))
			restores = append(restores, restoreFont)
			w, h := fbSize()
			log.Printf("консоль %s: экран %dx%d, шрифт %q", dev, w, h, font)
		}
		c.cols = consoleCols(int(f.Fd()))
		out = append(out, c)
	}
	return out, func() {
		for _, r := range restores {
			r()
		}
		for _, c := range out {
			_ = c.f.Close()
		}
	}
}

func isVirtualTerminal(dev string) bool {
	name := strings.TrimPrefix(dev, "/dev/")
	if !strings.HasPrefix(name, "tty") {
		return false
	}
	_, err := strconv.Atoi(strings.TrimPrefix(name, "tty"))
	return err == nil
}

func (cs textConsoles) names() string {
	var names []string
	for _, c := range cs {
		names = append(names, strings.TrimPrefix(c.dev, "/dev/"))
	}
	return strings.Join(names, " ")
}

type textLine struct {
	text  string
	style string
}

const (
	stylePlain = "\x1b[1;97m"
	styleError = "\x1b[1;91m"
	styleHint  = "\x1b[0;37m"
	styleWarn  = "\x1b[1;93m"
)

func (cs textConsoles) draw(lines []textLine, label string) {
	const indent = "  "
	for _, c := range cs {
		width := c.cols - 2*len(indent)
		var b strings.Builder
		b.WriteString("\x1b[0m\x1b[H\x1b[2J\x1b[?25h\r\n")
		b.WriteString(indent + "\x1b[1;94m>_\x1b[0m\r\n\r\n")
		for _, l := range lines {
			for _, line := range wrapText(l.text, width) {
				b.WriteString(indent + l.style + line + "\x1b[0m\r\n")
			}
			b.WriteString("\r\n")
		}
		c.line = nil
		if label != "" {
			for _, line := range wrapText(diskcrypt.Text("vp:layout"), width) {
				b.WriteString(indent + styleHint + line + "\x1b[0m\r\n")
			}
			c.line = &starLine{w: c, prefix: indent + stylePlain + label + ":\x1b[0m "}
			b.WriteString(c.line.render())
		}
		_, _ = io.WriteString(c, b.String())
	}
}

type askResult struct {
	dev    string
	secret []byte
	err    error
}

func (cs textConsoles) ask(deadline time.Time, cancel <-chan struct{}) ([]byte, error) {
	if len(cs) == 0 {
		return nil, errors.New("нет ни одной консоли")
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return nil, err
	}
	defer unix.Close(pipe[0]) //nolint:errcheck
	defer unix.Close(pipe[1]) //nolint:errcheck
	var once sync.Once
	stop := func() { once.Do(func() { _, _ = unix.Write(pipe[1], []byte{0}) }) }

	results := make(chan askResult, len(cs))
	var wg sync.WaitGroup
	for _, c := range cs {
		wg.Add(1)
		go func(c *textConsole) {
			defer wg.Done()
			var tick func()
			if c.vt && c.line != nil {
				tick = func() { c.line.setCaps(capsLockOn(int(c.f.Fd()))) }
				tick()
			}
			echo := io.Writer(io.Discard)
			if c.line != nil {
				echo = c.line
			}
			secret, err := readSecretOpts(int(c.f.Fd()), echo, deadline, pipe[0], tick)
			results <- askResult{dev: c.dev, secret: secret, err: err}
		}(c)
	}
	var winner askResult
	got := false
	pending := len(cs)
	for !got && pending > 0 {
		select {
		case r := <-results:
			pending--
			switch {
			case r.err == nil:
				winner, got = r, true
			case errors.Is(r.err, errConsoleCancelled):
			default:

				log.Printf("консоль %s: ввод прерван: %v", r.dev, r.err)
				winner = r
			}
		case <-cancel:
			winner = askResult{err: errConsoleCancelled}
			pending = 0
		}
	}
	stop()
	wg.Wait()

	close(results)
	for r := range results {
		wipeBytes(r.secret)
	}
	for _, c := range cs {
		_, _ = io.WriteString(c, "\r\n")
	}
	if winner.err == nil && winner.secret == nil {
		return nil, errConsoleCancelled
	}
	return winner.secret, winner.err
}

func capsLockOn(fd int) bool {
	v, err := unix.IoctlGetInt(fd, kdGetKbdLED)
	return err == nil && v&ledCapsLock != 0
}

type starLine struct {
	w      io.Writer
	prefix string
	n      int
	caps   bool
	mu     sync.Mutex
}

func (l *starLine) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch string(p) {
	case "*":
		l.n++
	case "\b \b":
		if l.n > 0 {
			l.n--
		}
	default:

		l.n -= strings.Count(string(p), "\b \b")
		if l.n < 0 {
			l.n = 0
		}
	}
	_, err := io.WriteString(l.w, l.render())
	return len(p), err
}

func (l *starLine) setCaps(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.caps == on {
		return
	}
	l.caps = on
	_, _ = io.WriteString(l.w, l.render())
}

func (l *starLine) render() string {
	s := "\r\x1b[K" + l.prefix + strings.Repeat("*", l.n)
	if l.caps {
		hint := "   " + diskcrypt.Text("vp:caps")
		s += styleWarn + hint + "\x1b[0m\x1b[" + strconv.Itoa(len([]rune(hint))) + "D"
	}
	return s
}
