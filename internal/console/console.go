package console

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Level int

const (
	Unknown Level = iota
	Off
	OK
	Warn
	Bad
)

type Line struct {
	Key     string
	Label   string
	LabelEN string
	Level   Level
	Text    string
	Note    string
}

type Status struct {
	Level    Level
	Badge    string
	Headline string
	Lines    []Line
	Advice   []string
	Suggest  int
}

type Danger int

const (
	Safe Danger = iota
	Ask
	Guarded
)

type Result struct {
	Level Level
	Lines []string

	Quiet bool
}

type Action struct {
	Number  int
	Command string
	Title   string
	TitleEN string
	Danger  Danger

	Before func() Result
	Run    func(s *Session) Result
}

type Catalog struct {
	Product   string
	ProductEN string
	Version   string
	Status    func() Status
	Actions   []Action
}

const Exit = 0

const maxNumber = 9

var commandName = regexp.MustCompile(`^[a-z][a-z-]*$`)

func (c Catalog) Validate() error {
	if c.Product == "" || c.ProductEN == "" || !ascii(c.ProductEN) {
		return fmt.Errorf("нужны название и его запись латиницей")
	}
	numbers, commands := map[int]bool{}, map[string]bool{}
	for _, a := range c.Actions {
		switch {
		case a.Number <= Exit || a.Number > maxNumber:
			return fmt.Errorf("пункт «%s»: цифра %d вне 1–%d", a.Title, a.Number, maxNumber)
		case numbers[a.Number]:
			return fmt.Errorf("цифра %d занята дважды", a.Number)
		case !commandName.MatchString(a.Command):
			return fmt.Errorf("пункт «%s»: имя команды «%s» не латиницей", a.Title, a.Command)
		case commands[a.Command]:
			return fmt.Errorf("команда «%s» занята дважды", a.Command)
		case a.Title == "" || a.TitleEN == "" || !ascii(a.TitleEN):
			return fmt.Errorf("пункт %d: нужны название и его запись латиницей", a.Number)
		case a.Run == nil:
			return fmt.Errorf("пункт «%s» ничего не делает", a.Title)
		case a.Danger != Safe && a.Before == nil:
			return fmt.Errorf("пункт «%s» спрашивает подтверждение, не объясняя, что произойдёт", a.Title)
		}
		numbers[a.Number], commands[a.Command] = true, true
	}
	return nil
}

func (c Catalog) byNumber(n int) (Action, bool) {
	for _, a := range c.Actions {
		if a.Number == n {
			return a, true
		}
	}
	return Action{}, false
}

func (c Catalog) ByCommand(name string) (Action, bool) {
	for _, a := range c.Actions {
		if a.Command == name {
			return a, true
		}
	}
	return Action{}, false
}

func (c Catalog) Commands() []string {
	sorted := append([]Action(nil), c.Actions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
	names := make([]string, 0, len(sorted))
	for _, a := range sorted {
		names = append(names, a.Command)
	}
	return names
}

func (c Catalog) numbers() []int {
	out := []int{Exit}
	for _, a := range c.Actions {
		out = append(out, a.Number)
	}
	sort.Ints(out)
	return out
}

func Range(numbers []int) string {
	sorted := append([]int(nil), numbers...)
	sort.Ints(sorted)
	var parts []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", sorted[i], sorted[j]))
		} else {
			parts = append(parts, fmt.Sprint(sorted[i]))
		}
		i = j + 1
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func ascii(s string) bool {
	for _, r := range s {
		if r > 0x7e || r < 0x20 {
			return false
		}
	}
	return true
}
