package supportfmt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Reason string

const (
	NotOurs      Reason = "это не файл сведений: первая строка другая"
	BadEncoding  Reason = "кодировка не UTF-8"
	BadChar      Reason = "недопустимый знак"
	LineTooLong  Reason = "строка длиннее предела"
	BadStructure Reason = "разметка разделов нарушена"
	UnknownPart  Reason = "неизвестный раздел"
	RepeatedPart Reason = "раздел повторяется"
	PartTooLong  Reason = "раздел длиннее своего предела"
	CountsDiffer Reason = "счётчик строк или разделов не сходится"
	Unfinished   Reason = "файл оборван: нет завершающей строки"
	TooBig       Reason = "файл больше предела"
	TrailingData Reason = "после завершающей строки есть данные"
)

type Rejection struct {
	Reason Reason
	Line   int
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("%s (строка %d)", r.Reason, r.Line)
}

type PartInfo struct {
	ID    string
	Lines int

	At int
}

type Report struct {
	Header []string
	Parts  []PartInfo
	Lines  int
	Bytes  int64
}

func Check(in io.Reader, out io.Writer, set Set, maxBytes int64) (*Report, error) {
	c := &checker{r: bufio.NewReaderSize(in, MaxLineBytes+2), w: bufio.NewWriter(out), set: set, max: maxBytes}
	rep, err := c.run()
	if err != nil {
		return nil, err
	}
	if err := c.w.Flush(); err != nil {
		return nil, err
	}
	return rep, nil
}

type checker struct {
	r     *bufio.Reader
	w     *bufio.Writer
	set   Set
	max   int64
	line  int
	bytes int64
}

func (c *checker) reject(r Reason) error { return &Rejection{Reason: r, Line: c.line} }

func (c *checker) next() (string, bool, error) {
	raw, err := c.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		c.line++
		return "", false, c.reject(LineTooLong)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	if len(raw) == 0 {
		return "", false, nil
	}
	c.line++
	c.bytes += int64(len(raw))
	if c.max > 0 && c.bytes > c.max {
		return "", false, c.reject(TooBig)
	}

	if raw[len(raw)-1] != '\n' {
		return "", false, c.reject(Unfinished)
	}
	raw = raw[:len(raw)-1]
	if len(raw) > MaxLineBytes {
		return "", false, c.reject(LineTooLong)
	}
	if !utf8.Valid(raw) {
		return "", false, c.reject(BadEncoding)
	}
	s := string(raw)
	for _, r := range s {
		if !allowed(r) {
			return "", false, c.reject(BadChar)
		}
	}
	return s, true, nil
}

func (c *checker) emit(s string) error {
	_, err := c.w.WriteString(s + "\n")
	return err
}

func (c *checker) run() (*Report, error) {
	rep := &Report{}
	first, ok, err := c.next()

	var rej *Rejection
	if err != nil && !errors.As(err, &rej) {
		return nil, err
	}
	if err != nil || !ok || first != Magic {
		c.line = 1
		return nil, c.reject(NotOurs)
	}
	if err := c.emit(first); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var cur *Section
	lines := 0
	for {
		s, ok, err := c.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, c.reject(Unfinished)
		}
		switch {
		case strings.HasPrefix(s, fileClose):
			n, good := number(s, fileClose)
			if cur != nil || !good {
				return nil, c.reject(BadStructure)
			}
			if n != len(rep.Parts) {
				return nil, c.reject(CountsDiffer)
			}
			if err := c.emit(s); err != nil {
				return nil, err
			}
			if _, more, err := c.next(); err != nil {
				return nil, err
			} else if more {
				return nil, c.reject(TrailingData)
			}
			rep.Lines, rep.Bytes = c.line, c.bytes
			return rep, nil
		case strings.HasPrefix(s, sectionOpen):
			id, good := strings.CutSuffix(strings.TrimPrefix(s, sectionOpen), lineSuffix)
			if cur != nil || !good {
				return nil, c.reject(BadStructure)
			}
			sec, known := c.set[id]
			if !known {
				return nil, c.reject(UnknownPart)
			}
			if seen[id] {
				return nil, c.reject(RepeatedPart)
			}
			seen[id] = true
			cur, lines = &sec, 0
			rep.Parts = append(rep.Parts, PartInfo{ID: id, At: c.line})
		case strings.HasPrefix(s, sectionClose):
			rest, good := strings.CutSuffix(strings.TrimPrefix(s, sectionClose), lineSuffix)
			id, count, found := strings.Cut(rest, " строк: ")
			n, numErr := strconv.Atoi(count)
			if cur == nil || !good || !found || numErr != nil || id != cur.ID {
				return nil, c.reject(BadStructure)
			}
			if n != lines {
				return nil, c.reject(CountsDiffer)
			}
			rep.Parts[len(rep.Parts)-1].Lines = lines
			cur = nil
		case strings.HasPrefix(s, "=="):

			return nil, c.reject(BadStructure)
		case cur == nil:

			if len(rep.Parts) > 0 {
				return nil, c.reject(BadStructure)
			}
			if len(rep.Header) == MaxHeaderLines {
				return nil, c.reject(BadStructure)
			}
			rep.Header = append(rep.Header, s)
		default:
			lines++
			if lines > cur.MaxLines {
				return nil, c.reject(PartTooLong)
			}
		}
		if err := c.emit(s); err != nil {
			return nil, err
		}
	}
}

func number(s, prefix string) (int, bool) {
	rest, ok := strings.CutSuffix(strings.TrimPrefix(s, prefix), lineSuffix)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil && n >= 0
}
