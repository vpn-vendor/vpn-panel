package console

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type Style struct {
	Color bool
	Plain bool
	Width int
}

const defaultWidth = 80

var latinOnly = map[string]bool{"": true, "dumb": true, "vt100": true, "vt102": true, "vt220": true}

func Detect(out *os.File, env func(string) string) Style {
	st := Style{Width: defaultWidth}
	ws, err := unix.IoctlGetWinsize(int(out.Fd()), unix.TIOCGWINSZ)
	tty := err == nil
	if tty && ws.Col > 0 {
		st.Width = int(ws.Col)
	}
	term := env("TERM")

	st.Plain = !utf8Locale(env) || (tty && latinOnly[term])

	st.Color = tty && term != "dumb" && term != "" && env("NO_COLOR") == ""
	return st
}

func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func utf8Locale(env func(string) string) bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := env(name); v != "" {
			v = strings.ToUpper(v)
			return strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8")
		}
	}
	return false
}

const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrDim    = "\x1b[90m"
	sgrNumber = "\x1b[96m"
	sgrHint   = "\x1b[93m"
	sgrYes    = "\x1b[1;92m"
	sgrNo     = "\x1b[1;91m"
)

var badgeColor = map[Level]string{
	OK:      "\x1b[30;42m",
	Warn:    "\x1b[30;43m",
	Bad:     "\x1b[97;41m",
	Unknown: "\x1b[30;47m",
	Off:     "\x1b[30;47m",
}

var levelEN = map[Level]string{OK: "OK", Warn: "WARNING", Bad: "FAILED", Unknown: "UNKNOWN", Off: "OFF"}

func (st Style) paint(code, text string) string {
	if !st.Color {
		return text
	}
	return code + text + sgrReset
}

func (st Style) badge(level Level, text string) string {
	if !st.Color {
		return "[" + text + "]"
	}
	return badgeColor[level] + " " + text + " " + sgrReset
}
