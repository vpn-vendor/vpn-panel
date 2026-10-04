package diskpass

import (
	"bufio"
	"io"
	"strings"
)

type Reason string

const (
	OK       Reason = ""
	NotLatin Reason = "latin"
	Short    Reason = "short"
	Trivial  Reason = "trivial"
	Common   Reason = "common"
	Context  Reason = "context"
)

const MinLength = 12

const minContext = 4

var sequences = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"0123456789",
	"qwertyuiop", "asdfghjkl", "zxcvbnm",
	"qwertyuiopasdfghjklzxcvbnm",
	"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
	"`1234567890-=",
}

type Policy struct {
	common  map[string]struct{}
	context []string
}

func NewPolicy(common io.Reader, context ...string) (*Policy, error) {
	p := &Policy{common: make(map[string]struct{})}
	sc := bufio.NewScanner(common)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p.common[strings.ToLower(line)] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, w := range context {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) >= minContext {
			p.context = append(p.context, w)
		}
	}
	return p, nil
}

func (p *Policy) Check(pw string) Reason {
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x20 || pw[i] > 0x7e {
			return NotLatin
		}
	}
	if len(pw) < MinLength {
		return Short
	}
	low := strings.ToLower(pw)
	if trivial(low) {
		return Trivial
	}
	if _, ok := p.common[low]; ok {
		return Common
	}
	for _, w := range p.context {
		if strings.Contains(low, w) {
			return Context
		}
	}
	return OK
}

func trivial(low string) bool {
	if strings.Count(low, low[:1]) == len(low) {
		return true
	}
	for _, s := range sequences {
		ring := s + s
		if strings.Contains(ring, low) || strings.Contains(ring, reverse(low)) {
			return true
		}
	}
	return false
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
