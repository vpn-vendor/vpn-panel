package console

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ExitOK      = 0
	ExitFailed  = 1
	ExitUnknown = 2
)

func Run(c Catalog, s *Session) int {
	for {
		c.screen(s)
		n, ok := s.Choose(c.numbers())
		if !ok || n == Exit {
			return ExitOK
		}
		a, _ := c.byNumber(n)
		s.printf("\n")
		if !c.execute(a, s).Quiet {
			s.Pause()
		}
		s.printf("\n")
	}
}

func RunCommand(c Catalog, program, name string, s *Session) int {
	if IsHelp(name) {
		c.Usage(program, s)
		return ExitOK
	}
	a, ok := c.ByCommand(name)
	if !ok {
		s.printf(s.say(sayUnknown)+"\n\n", name)
		c.Usage(program, s)
		return ExitUnknown
	}
	if c.execute(a, s).Level == Bad {
		return ExitFailed
	}
	return ExitOK
}

const CompleteWord = "__complete"

func IsHelp(word string) bool { return word == "help" || word == "--help" || word == "-h" }

func (c Catalog) Words() []string { return append(c.Commands(), "help") }

func (c Catalog) Usage(program string, s *Session) {
	s.printf(s.say(sayUsage)+"\n", program)
	s.printf("%s\n\n", s.say(sayNoArgs))
	width := 0
	for _, name := range c.Commands() {
		if len(name) > width {
			width = len(name)
		}
	}
	for _, name := range c.Commands() {
		a, _ := c.ByCommand(name)
		s.printf("  %s%s  %s\n", name, strings.Repeat(" ", width-len(name)), s.title(a))
	}
}

func (c Catalog) execute(a Action, s *Session) Result {
	s.Heading(s.title(a))
	if a.Before != nil {
		s.Show(a.Before())
		s.printf("\n")
	}
	confirmed := true
	switch a.Danger {
	case Ask:
		confirmed = s.Confirm()
	case Guarded:
		confirmed = s.ConfirmGuarded()
	}
	if !confirmed {
		res := Result{Level: Unknown, Lines: []string{s.say(sayCancelled)}}
		s.Show(res)
		return res
	}
	res := a.Run(s)
	s.Show(res)
	return res
}

func (s *Session) Heading(text string) {
	s.printf("%s\n%s\n", s.Style.paint(sgrBold, text), s.rule())
}

func (s *Session) title(a Action) string {
	if s.Style.Plain {
		return a.TitleEN
	}
	return a.Title
}

func (s *Session) width() int {
	if s.Style.Width > 0 && s.Style.Width < defaultWidth {
		return s.Style.Width
	}
	return defaultWidth
}

func (s *Session) rule() string {
	ch := "─"
	if s.Style.Plain {
		ch = "-"
	}
	return s.Style.paint(sgrDim, strings.Repeat(ch, s.width()))
}

func (c Catalog) screen(s *Session) {
	st := Status{}
	if c.Status != nil {
		st = c.Status()
	}
	product, version := c.Product, s.say(sayVersion)+c.Version
	if s.Style.Plain {
		product = c.ProductEN
	}
	gap := s.width() - utf8.RuneCountInString(product) - utf8.RuneCountInString(version)
	if gap < 1 {
		gap = 1
	}
	s.printf("%s%s%s\n%s\n", s.Style.paint(sgrBold, product), strings.Repeat(" ", gap),
		s.Style.paint(sgrDim, version), s.rule())
	if s.Style.Plain {
		s.printf(" %s\n %s\n", sayPlain.en, sayPlainHow.en)
	}

	if st.Badge != "" && !s.Style.Plain {
		s.printf(" %s  %s\n", s.Style.badge(st.Level, st.Badge), st.Headline)
	}
	s.printf("\n")
	s.Lines(st.Lines)
	if len(st.Lines) > 0 {
		s.printf("\n")
	}
	if !s.Style.Plain {
		for _, line := range st.Advice {
			s.printf(" %s\n", s.Style.paint(sgrHint, line))
		}
		if len(st.Advice) > 0 {
			s.printf("\n")
		}
	}

	actions := append([]Action(nil), c.Actions...)
	sort.Slice(actions, func(i, j int) bool { return actions[i].Number < actions[j].Number })
	for _, a := range actions {
		if a.Number == st.Suggest {
			s.printf("  %s\n", s.Style.paint(sgrHint, itemText(a.Number, s.title(a))+"   "+s.say(sayStartHere)))
			continue
		}
		s.printf("  %s  %s\n", s.Style.paint(sgrNumber, digit(a.Number)), s.title(a))
	}
	s.printf("  %s  %s\n\n", s.Style.paint(sgrNumber, digit(Exit)), s.say(sayExit))
}

func digit(n int) string { return strconv.Itoa(n) }

func itemText(n int, title string) string { return digit(n) + "  " + title }
