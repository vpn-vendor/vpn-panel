package console

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type Session struct {
	in    *bufio.Reader
	out   io.Writer
	Style Style

	Code func() string
}

func NewSession(in io.Reader, out io.Writer, st Style, code func() string) *Session {
	return &Session{in: bufio.NewReader(in), out: out, Style: st, Code: code}
}

type phrase struct{ ru, en string }

var (
	sayPrompt    = phrase{"Введите цифру и нажмите Enter %s: ", "Type a digit and press Enter %s: "}
	sayRetry     = phrase{"Нужна одна цифра из %s.", "One digit from %s, please."}
	sayYes       = phrase{" — да, ", " - yes, "}
	sayNo        = phrase{" — нет", " - no"}
	sayYesNoAsk  = phrase{"Введите y или n и нажмите Enter [y/n]: ", "Type y or n and press Enter [y/n]: "}
	sayYesNoBad  = phrase{"Нужна буква y (да) или n (нет).", "Please type y (yes) or n (no)."}
	sayGuardWarn = phrase{"Это нельзя отменить.", "This cannot be undone."}
	sayGuard     = phrase{"Чтобы подтвердить, введите число %s (0 — отказаться): ", "Type %s to confirm (0 to cancel): "}
	sayCancelled = phrase{"Отменено — ничего не изменилось.", "Cancelled - nothing changed."}
	sayPause     = phrase{"Enter — вернуться в меню: ", "Press Enter to return: "}
	sayExit      = phrase{"Выход", "Exit"}
	sayStartHere = phrase{"← начните отсюда", "<- start here"}
	sayVersion   = phrase{"версия ", "version "}
	sayUsage     = phrase{"Использование: sudo %s [команда]", "Usage: sudo %s [command]"}
	sayNoArgs    = phrase{"Без команды открывается меню.", "Without a command the menu opens."}
	sayUnknown   = phrase{"Такой команды нет: %s", "No such command: %s"}
	sayPlain     = phrase{"", "Russian text is not readable on this terminal."}
	sayPlainHow  = phrase{"", "Use the server screen or SSH for the full text."}
)

func (s *Session) say(p phrase) string {
	if s.Style.Plain {
		return p.en
	}
	return p.ru
}

func (s *Session) printf(format string, args ...any) { _, _ = fmt.Fprintf(s.out, format, args...) }

const maxAnswer = 32

func (s *Session) answer() (string, bool) {
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	line = strings.TrimSpace(line)
	if len(line) > maxAnswer {
		line = line[:maxAnswer]
	}
	return line, true
}

func (s *Session) Choose(allowed []int) (int, bool) {
	for {
		s.printf(" "+s.say(sayPrompt), Range(allowed))
		line, ok := s.answer()
		if !ok {
			s.printf("\n")
			return Exit, false
		}
		if len(line) == 1 && line[0] >= '0' && line[0] <= '9' {
			n := int(line[0] - '0')
			for _, a := range allowed {
				if a == n {
					return n, true
				}
			}
		}
		s.printf(" "+s.say(sayRetry)+"\n", Range(allowed))
	}
}

var (
	answersYes = map[string]bool{"y": true, "Y": true, "д": true, "Д": true}
	answersNo  = map[string]bool{"n": true, "N": true, "н": true, "Н": true}
)

func (s *Session) Confirm() bool {
	s.printf(" %s%s%s%s\n", s.Style.paint(sgrYes, "y"), s.say(sayYes), s.Style.paint(sgrNo, "n"), s.say(sayNo))
	for {
		s.printf(" %s", s.say(sayYesNoAsk))
		line, ok := s.answer()
		switch {
		case !ok:
			s.printf("\n")
			return false
		case answersYes[line]:
			return true
		case answersNo[line]:
			return false
		}
		s.printf(" %s\n", s.say(sayYesNoBad))
	}
}

func (s *Session) ConfirmGuarded() bool {
	want := s.Code()
	s.printf(" %s\n "+s.say(sayGuard), s.say(sayGuardWarn), want)
	line, ok := s.answer()
	return ok && line == want
}

func (s *Session) Pause() {
	s.printf("\n %s", s.say(sayPause))
	if _, ok := s.answer(); !ok {
		s.printf("\n")
	}
}

func (s *Session) Print(lines ...string) {
	for _, line := range lines {
		if line == "" {
			s.printf("\n")
			continue
		}
		for _, part := range s.fold(line) {
			s.printf(" %s\n", part)
		}
	}
}

func (s *Session) Lines(lines []Line) {
	label := func(l Line) string {
		if s.Style.Plain {
			return l.LabelEN
		}
		return l.Label
	}
	width := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(label(l)); n > width {
			width = n
		}
	}
	for _, l := range lines {
		text, note := l.Text, l.Note
		if s.Style.Plain {
			text, note = levelEN[l.Level], ""
		}
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(label(l)))
		row := " " + label(l) + pad + "   " + s.Style.badge(l.Level, text)
		if note != "" {
			row += "   " + s.Style.paint(sgrDim, note)
		}
		s.printf("%s\n", row)
	}
}

func (s *Session) Steps(steps []string) {
	for i, step := range steps {
		prefix := fmt.Sprintf("%d. ", i+1)
		for _, part := range foldTo(step, s.width()-2-len(prefix)) {
			s.printf(" %s%s\n", prefix, part)
			prefix = strings.Repeat(" ", len(prefix))
		}
	}
}

func (s *Session) fold(line string) []string { return foldTo(line, s.width()-2) }

func foldTo(line string, room int) []string {
	if utf8.RuneCountInString(line) <= room {
		return []string{line}
	}
	indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
	var out []string
	current := indent
	for _, word := range strings.Fields(line) {
		switch {
		case current == indent:
			current += word
		case utf8.RuneCountInString(current)+1+utf8.RuneCountInString(word) > room:
			out = append(out, current)
			current = indent + word
		default:
			current += " " + word
		}
	}
	return append(out, current)
}

func (s *Session) Show(r Result) {
	for i, line := range r.Lines {
		for _, part := range s.fold(line) {
			if i == 0 && r.Level != Unknown {
				part = s.Style.paint(resultColor[r.Level], part)
			}
			s.printf(" %s\n", part)
		}
	}
}

var resultColor = map[Level]string{OK: "\x1b[92m", Warn: "\x1b[93m", Bad: "\x1b[91m"}
