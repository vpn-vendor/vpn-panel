package supportfmt

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Magic = "VPN-PANEL-SUPPORT 1"

const MaxLineBytes = 2000

const MaxHeaderLines = 32

const (
	sectionOpen  = "== раздел: "
	sectionClose = "== конец: "
	fileClose    = "== конец файла: разделов: "
	lineSuffix   = " =="

	truncated = "… раздел обрезан: достигнут предел строк"
)

type Section struct {
	ID    string
	Title string

	MaxLines int
}

type Set map[string]Section

func NewSet(sections ...Section) (Set, error) {
	out := Set{}
	for _, s := range sections {
		if !validID(s.ID) || s.MaxLines <= 0 {
			return nil, fmt.Errorf("supportfmt: негодный раздел %q", s.ID)
		}
		if _, dup := out[s.ID]; dup {
			return nil, fmt.Errorf("supportfmt: раздел %q объявлен дважды", s.ID)
		}
		out[s.ID] = s
	}
	return out, nil
}

func validID(id string) bool {
	if id == "" || len(id) > 40 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func allowed(r rune) bool {
	if r == ' ' {
		return true
	}
	if r == utf8.RuneError || r > unicode.MaxRune {
		return false
	}
	return unicode.IsGraphic(r) && !unicode.Is(unicode.Zs, r) && !unicode.Is(unicode.Co, r)
}

func Escape(s string) string {
	clean := true
	for _, r := range s {
		if r == '\\' || !allowed(r) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02X`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case allowed(r):
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u{%X}`, r)
		}
		i += size
	}
	return b.String()
}

func cut(s string) string {
	if len(s) <= MaxLineBytes {
		return s
	}
	const mark = " …"
	end := MaxLineBytes - len(mark)
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + mark
}

type Writer struct {
	w        io.Writer
	set      Set
	err      error
	sections int
	cur      *Section
	lines    int
	full     bool
	seen     map[string]bool
}

func NewWriter(w io.Writer, set Set, header [][2]string) *Writer {
	sw := &Writer{w: w, set: set, seen: map[string]bool{}}
	sw.raw(Magic)
	for _, kv := range header {
		sw.raw(cut(Escape(kv[0] + ": " + kv[1])))
	}
	return sw
}

func (w *Writer) raw(line string) {
	if w.err != nil {
		return
	}
	_, w.err = io.WriteString(w.w, line+"\n")
}

func (w *Writer) Begin(id string) error {
	if w.cur != nil {
		w.End()
	}
	s, ok := w.set[id]
	if !ok || w.seen[id] {
		return fmt.Errorf("supportfmt: раздел %q неизвестен или уже записан", id)
	}
	w.seen[id] = true
	w.cur, w.lines, w.full = &s, 0, false
	w.raw(sectionOpen + id + lineSuffix)
	return nil
}

func (w *Writer) Line(text string) {
	if w.cur == nil {
		return
	}
	for _, part := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if w.full {
			return
		}
		if w.lines == w.cur.MaxLines-1 {
			w.raw(truncated)
			w.lines++
			w.full = true
			return
		}
		line := cut(Escape(strings.TrimRight(part, "\r")))

		if strings.HasPrefix(line, "==") {
			line = `\` + line
		}
		w.raw(line)
		w.lines++
	}
}

func (w *Writer) End() {
	if w.cur == nil {
		return
	}
	w.raw(fmt.Sprintf("%s%s строк: %d%s", sectionClose, w.cur.ID, w.lines, lineSuffix))
	w.cur = nil
	w.sections++
}

func (w *Writer) Close() error {
	w.End()
	w.raw(fmt.Sprintf("%s%d%s", fileClose, w.sections, lineSuffix))
	return w.err
}
