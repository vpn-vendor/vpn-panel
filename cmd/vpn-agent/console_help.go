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

func (d helpDesk) run(s *console.Session) console.Result {

	if s.Style.Plain {
		return console.Result{Lines: []string{"Help is written in Russian.", "Open it on the server screen or over SSH."}}
	}
	allowed := []int{console.Exit}
	var list []string
	for _, t := range help.Topics() {
		allowed = append(allowed, t.Number)
		list = append(list, fmt.Sprintf(" %d  %s", t.Number, t.Question))
	}
	s.Print(append(list, fmt.Sprintf(" %d  Назад", console.Exit), "")...)
	n, ok := s.Choose(allowed)
	if !ok || n == console.Exit {
		return console.Result{Quiet: true}
	}
	topic, _ := help.ByNumber(n)
	d.show(s, topic)
	return console.Result{}
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
	for _, name := range t.Actions {
		for _, a := range d.actions {
			if a.Command == name {
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
	action := func(name string) bool { _, ok := c.ByCommand(name); return ok }
	return help.Validate(help.Topics(), action, func(string) bool { return true })
}
