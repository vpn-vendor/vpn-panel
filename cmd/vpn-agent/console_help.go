package main

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/internal/console"
	"github.com/vpn-vendor/vpn-panel-core/internal/help"
)

type helpDesk struct {
	actions []console.Action
	status  func() console.Status
}

var intentCommand = map[help.Intent]string{
	help.IntentCode: "code", help.IntentRestart: "restart", help.IntentSupport: "support",
	help.IntentBackup: "backup", help.IntentSignOut: "signout",
}

const (
	helpPageSize = 8
	helpMore     = 9
)

var topicsForConsole = help.Topics

func (d helpDesk) run(s *console.Session) console.Result {

	if s.Style.Plain {
		return console.Result{Lines: []string{"Help is written in Russian.", "Open it on the server screen or over SSH."}}
	}
	topics := topicsForConsole()
	for from := 0; ; {
		page := topics[from:min(from+helpPageSize, len(topics))]
		more := from+helpPageSize < len(topics)
		allowed := []int{console.Exit}
		var list []string
		for i, t := range page {
			allowed = append(allowed, i+1)
			list = append(list, fmt.Sprintf(" %d  %s", i+1, t.Question))
		}
		if more {
			allowed = append(allowed, helpMore)
			list = append(list, fmt.Sprintf(" %d  Дальше (ещё %d)", helpMore, len(topics)-from-helpPageSize))
		}
		s.Print(append(list, fmt.Sprintf(" %d  Назад", console.Exit), "")...)
		n, ok := s.Choose(allowed)
		switch {
		case !ok || n == console.Exit:
			return console.Result{Quiet: true}
		case n == helpMore && more:
			from += helpPageSize
			s.Print("")
			continue
		}
		d.show(s, page[n-1])
		return console.Result{}
	}
}

func (d helpDesk) show(s *console.Session, t help.Topic) {
	s.Print("")
	s.Heading(t.Question)
	if lines := d.checked(t.Checks); len(lines) > 0 {
		s.Print("Проверено сейчас:")
		s.Lines(lines)
		s.Print("")
	}
	s.Print("Что делать:")
	s.Steps(t.Steps)
	var items []string
	for _, intent := range t.Intents {
		for _, a := range d.actions {
			if a.Command == intentCommand[intent] {
				items = append(items, fmt.Sprintf("  %d  %s", a.Number, a.Title))
			}
		}
	}
	if len(items) > 0 {
		s.Print(append([]string{"", "Пункты меню, которые здесь помогут:"}, items...)...)
	}
}

func (d helpDesk) checked(checks []help.Check) []console.Line {
	if len(checks) == 0 {
		return nil
	}
	var out []console.Line
	st := d.status()
	for _, c := range checks {
		for _, line := range st.Lines {
			if line.Key == string(c) {
				out = append(out, line)
			}
		}
	}
	return out
}

func validConsole(c console.Catalog) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := help.Validate(help.Topics(), func(string) bool { return true }); err != nil {
		return err
	}
	for _, t := range help.Topics() {
		for _, intent := range t.Intents {
			if _, ok := c.ByCommand(intentCommand[intent]); !ok {
				return fmt.Errorf("тема «%s»: намерению «%s» не назначен пункт меню", t.Question, intent)
			}
		}
	}
	return nil
}
