package main

import (
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

const (
	consoleTTY   = "/dev/tty1"
	consoleFonts = "/usr/share/consolefonts"

	consoleRowsOnScreen = 36

	consoleMaxSecret = 512

	consoleReadFinal = 3 * time.Second

	consoleTakeover     = 3 * time.Second
	consoleTakeoverPoll = 50 * time.Millisecond
)

type consoleFontSize struct {
	height, width int
	file          string
}

var consoleFontSizes = []consoleFontSize{
	{32, 16, "Uni2-TerminusBold32x16.psf.gz"},
	{28, 14, "Uni2-TerminusBold28x14.psf.gz"},
	{24, 12, "Uni2-TerminusBold24x12.psf.gz"},
	{22, 11, "Uni2-TerminusBold22x11.psf.gz"},
	{20, 10, "Uni2-TerminusBold20x10.psf.gz"},
	{18, 10, "Uni2-TerminusBold18x10.psf.gz"},
	{16, 8, "Uni2-TerminusBold16.psf.gz"},
	{14, 8, "Uni2-TerminusBold14.psf.gz"},
}

var errConsoleTimeout = errors.New("нет ответа на консоли")

var (
	consoleErrors = map[diskcrypt.Message]bool{
		diskcrypt.MsgCurrentWrong: true, diskcrypt.MsgSame: true, diskcrypt.MsgMismatch: true,
		diskcrypt.ReasonMessage(diskpass.NotLatin): true, diskcrypt.ReasonMessage(diskpass.Short): true,
		diskcrypt.ReasonMessage(diskpass.Trivial): true, diskcrypt.ReasonMessage(diskpass.Common): true,
		diskcrypt.ReasonMessage(diskpass.Context): true, diskcrypt.MsgChangeFailed: true,
	}
	consoleFinal = map[diskcrypt.Message]bool{
		diskcrypt.MsgChanged: true, diskcrypt.MsgKept: true, diskcrypt.MsgChangeFailed: true,
	}
)

type consoleHuman struct {
	tty     *os.File
	timeout time.Duration
	cols    int
	intro   string
	note    diskcrypt.Message
}

func newConsoleHuman(timeout time.Duration) (h *consoleHuman, restore func(), err error) {
	if ply, err := findBinary([]string{"/usr/bin/plymouth", "/bin/plymouth"}); err == nil {

		_ = exec.Command(ply, "quit").Run() //nolint:gosec
	}
	if chvt, err := findBinary([]string{"/usr/bin/chvt", "/bin/chvt"}); err == nil {
		_ = exec.Command(chvt, "1").Run() //nolint:gosec
	}

	tty, err := os.OpenFile(consoleTTY, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, func() {}, err
	}

	_, _ = io.WriteString(tty, "\x1b[H\x1b[2J.\r")
	waitConsoleTakeover()
	font, restoreFont := consoleFont(int(tty.Fd()))
	h = &consoleHuman{tty: tty, timeout: timeout, cols: consoleCols(int(tty.Fd()))}
	w, hgt := fbSize()
	log.Printf("disk-change: консоль: экран %dx%d, шрифт %s, колонок %d", w, hgt, font, h.cols)
	return h, func() {
		restoreFont()
		_ = tty.Close()
	}, nil
}

func waitConsoleTakeover() {
	deadline := time.Now().Add(consoleTakeover)
	for time.Now().Before(deadline) {
		if consoleOnFramebuffer() {
			return
		}
		time.Sleep(consoleTakeoverPoll)
	}
	log.Print("disk-change: консоль не перешла к драйверу экрана")
}

func consoleOnFramebuffer() bool {
	dirs, err := filepath.Glob("/sys/class/vtconsole/vtcon*")
	if err != nil {
		return false
	}
	for _, d := range dirs {
		name, err1 := os.ReadFile(filepath.Join(d, "name")) //nolint:gosec
		bind, err2 := os.ReadFile(filepath.Join(d, "bind")) //nolint:gosec
		if err1 == nil && err2 == nil && strings.TrimSpace(string(bind)) == "1" &&
			strings.Contains(string(name), "frame buffer") {
			return true
		}
	}
	return false
}

func consoleFont(fd int) (font string, restore func()) {
	setfont, err := findBinary([]string{"/usr/bin/setfont", "/bin/setfont"})
	if err != nil {
		log.Printf("disk-change: шрифт консоли: %v", err)
		return "", func() {}
	}
	screenW, screenH := fbSize()
	f := pickConsoleFont(screenH)
	deadline := time.Now().Add(consoleTakeover)
	for {

		if out, err := exec.Command(setfont, "-C", consoleTTY, consoleFonts+"/"+f.file).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("disk-change: шрифт консоли не включён: %v: %s", err, lastLine(out))
			return "", func() {}
		}
		if screenW <= 0 || consoleCols(fd) == screenW/f.width {
			break
		}
		if time.Now().After(deadline) {
			log.Printf("disk-change: шрифт консоли не применился: колонок %d, ждали %d", consoleCols(fd), screenW/f.width)
			break
		}
		time.Sleep(consoleTakeoverPoll)
	}
	return f.file, func() {
		setupcon, err := findBinary([]string{"/usr/bin/setupcon", "/bin/setupcon"})
		if err != nil {
			return
		}
		if out, err := exec.Command(setupcon, "--force", "--font-only").CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("шрифт системы не возвращён: %v: %s", err, lastLine(out))
		}
	}
}

func fbSize() (w, h int) {
	data, err := os.ReadFile("/sys/class/graphics/fb0/virtual_size")
	if err != nil {
		return 0, 0
	}
	ws, hs, ok := strings.Cut(strings.TrimSpace(string(data)), ",")
	if !ok {
		return 0, 0
	}
	w, errW := strconv.Atoi(ws)
	h, errH := strconv.Atoi(hs)
	if errW != nil || errH != nil {
		return 0, 0
	}
	return w, h
}

func consoleCols(fd int) int {
	if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
		return int(ws.Col)
	}
	return 80
}

func wrapText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var lines []string
	var line []rune
	for _, word := range strings.Fields(text) {
		w := []rune(word)
		for len(w) > width {
			if len(line) > 0 {
				lines = append(lines, string(line))
				line = nil
			}
			lines = append(lines, string(w[:width]))
			w = w[width:]
		}
		switch {
		case len(line) == 0:
			line = w
		case len(line)+1+len(w) <= width:
			line = append(append(line, ' '), w...)
		default:
			lines = append(lines, string(line))
			line = w
		}
	}
	if len(line) > 0 {
		lines = append(lines, string(line))
	}
	return lines
}

func pickConsoleFont(screenH int) consoleFontSize {
	if screenH <= 0 {
		return consoleFontSizes[len(consoleFontSizes)-2]
	}
	for _, f := range consoleFontSizes {
		if f.height*consoleRowsOnScreen <= screenH {
			return f
		}
	}
	return consoleFontSizes[len(consoleFontSizes)-1]
}

func (h *consoleHuman) Tell(m diskcrypt.Message) error {
	switch {
	case m == diskcrypt.MsgChangeIntro:
		h.intro = diskcrypt.Text(string(m))
		return nil
	case consoleFinal[m]:
		h.draw("", m)
		time.Sleep(consoleReadFinal)
		return nil
	default:
		h.note = m
		return nil
	}
}

func (h *consoleHuman) Ask(p diskcrypt.Prompt) ([]byte, error) {
	h.draw(diskcrypt.Text(string(p)), h.note)
	h.note = ""
	secret, err := readSecret(int(h.tty.Fd()), h.tty, h.timeout)
	_, _ = io.WriteString(h.tty, "\r\n")
	return secret, err
}

func (h *consoleHuman) draw(label string, note diskcrypt.Message) {
	const indent = "  "

	width := h.cols - 2*len(indent)
	para := func(b *strings.Builder, text, color string) {
		for _, line := range wrapText(text, width) {
			b.WriteString(indent + color + line + "\x1b[0m\r\n")
		}
		b.WriteString("\r\n")
	}
	var b strings.Builder
	b.WriteString("\x1b[0m\x1b[H\x1b[2J\x1b[?25h\r\n")
	b.WriteString(indent + "\x1b[1;94m>_\x1b[0m\r\n\r\n")
	if h.intro != "" {
		para(&b, h.intro, "")
	}
	if note != "" {
		color := "\x1b[1;97m"
		if consoleErrors[note] {
			color = "\x1b[1;91m"
		}
		para(&b, diskcrypt.Text(string(note)), color)
	}
	if label != "" {
		para(&b, diskcrypt.Text("vp:layout"), "\x1b[2m")
		b.WriteString(indent + "\x1b[1;97m" + label + ":\x1b[0m ")
	}
	_, _ = io.WriteString(h.tty, b.String())
}

func readSecret(fd int, echo io.Writer, timeout time.Duration) ([]byte, error) {
	if st, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		raw := *st
		raw.Lflag &^= unix.ECHO | unix.ICANON
		raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err == nil {
			defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, st) }()
		}

		_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
	}
	deadline := time.Now().Add(timeout)

	secret := make([]byte, 0, consoleMaxSecret)

	const (
		plain = iota
		escape
		csi
		ss3
	)
	state := plain
	buf := make([]byte, 64)
	defer wipeBytes(buf)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			wipeBytes(secret)
			return nil, errConsoleTimeout
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} //nolint:gosec
		n, err := unix.Poll(fds, int(left.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			wipeBytes(secret)
			return nil, err
		}
		if n == 0 {
			continue
		}
		got, err := unix.Read(fd, buf)
		if err != nil || got == 0 {
			wipeBytes(secret)
			if err == nil {
				err = io.EOF
			}
			return nil, err
		}
		for _, c := range buf[:got] {
			switch state {
			case escape:
				switch c {
				case '[':
					state = csi
				case 'O':
					state = ss3
				default:
					state = plain
				}
				continue
			case csi:
				if c >= 0x40 && c <= 0x7e {
					state = plain
				}
				continue
			case ss3:
				state = plain
				continue
			}
			switch {
			case c == 0x1b:
				state = escape
			case c == '\r' || c == '\n':
				return secret, nil
			case c == 0x7f || c == 0x08:
				if len(secret) > 0 {
					secret[len(secret)-1] = 0
					secret = secret[:len(secret)-1]
					_, _ = io.WriteString(echo, "\b \b")
				}
			case c == 0x15:
				_, _ = io.WriteString(echo, strings.Repeat("\b \b", len(secret)))
				wipeBytes(secret)
				secret = secret[:0]
			case c >= 0x20 && c < 0x7f && len(secret) < consoleMaxSecret:
				secret = append(secret, c)
				_, _ = io.WriteString(echo, "*")
			}
		}
	}
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
