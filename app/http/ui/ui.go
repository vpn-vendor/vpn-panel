package ui

import (
	"strconv"
	"strings"
)

type Field struct {
	ID           string
	Name         string
	Label        string
	Value        string
	Type         string
	Placeholder  string
	Hint         string
	Error        string
	Required     bool
	Disabled     bool
	Autocomplete string
	MaxLength    int
	Min, Max     string
}

func (f Field) InputType() string {
	if f.Type == "" {
		return "text"
	}
	return f.Type
}

func (f Field) HasError() bool { return strings.TrimSpace(f.Error) != "" }

func (f Field) DescribedBy() string {
	switch {
	case f.HasError():
		return f.ID + "-error"
	case strings.TrimSpace(f.Hint) != "":
		return f.ID + "-hint"
	}
	return ""
}

type Option struct {
	Value    string
	Label    string
	Disabled bool
}

type Select struct {
	ID       string
	Name     string
	Label    string
	Value    string
	Hint     string
	Error    string
	Disabled bool
	Options  []Option
}

func (s Select) HasError() bool { return strings.TrimSpace(s.Error) != "" }

func (s Select) IsChosen(o Option) bool { return o.Value == s.Value }

func (s Select) DescribedBy() string {
	switch {
	case s.HasError():
		return s.ID + "-error"
	case strings.TrimSpace(s.Hint) != "":
		return s.ID + "-hint"
	}
	return ""
}

type Toggle struct {
	ID       string
	Name     string
	Label    string
	Hint     string
	Checked  bool
	Disabled bool
	Value    string
}

func (t Toggle) FormValue() string {
	if t.Value == "" {
		return "1"
	}
	return t.Value
}

type FileField struct {
	ID       string
	Name     string
	Label    string
	Hint     string
	Accept   string
	Required bool
}

func (f FileField) DescribedBy() string {
	if strings.TrimSpace(f.Hint) != "" {
		return f.ID + "-hint"
	}
	return ""
}

type DangerRow struct {
	Name  string
	Title string
	Item  string
	Kind  string
	Warn  string
}

type DangerConfirm struct {
	Word   string
	Rows   []DangerRow
	Error  string
	Submit Button
}

type Button struct {
	Label    string
	Type     string
	Kind     string
	Small    bool
	Disabled bool
	Name     string
	Value    string
}

func (b Button) ButtonType() string {
	if b.Type == "" {
		return "submit"
	}
	return b.Type
}

func (b Button) Class() string {
	class := "btn"
	switch b.Kind {
	case "", "primary":
	case "secondary", "danger", "ghost":
		class += " btn-" + b.Kind
	default:

	}
	if b.Small {
		class += " btn-small"
	}
	return class
}

type Level string

const (
	None Level = ""
	OK   Level = "ok"
	Warn Level = "warn"
	Bad  Level = "error"
)

type Judgment struct {
	level Level
	owner string
}

func Judge(level Level, owner string) Judgment {
	switch level {
	case OK, Warn, Bad:
	default:
		return Judgment{}
	}
	if strings.TrimSpace(owner) == "" {
		return Judgment{}
	}
	return Judgment{level: level, owner: owner}
}

func (j Judgment) Level() Level { return j.level }

func (j Judgment) Owner() string { return j.owner }

type Metric struct {
	Label  string
	Value  string
	Unit   string
	Note   string
	Judged Judgment
}

func (m Metric) Class() string {
	if l := m.Judged.Level(); l != None {
		return "metric metric-" + string(l)
	}
	return "metric"
}

type ChartRow struct {
	Name   string
	Label  string
	Value  string
	Series int
}

func (r ChartRow) Shown() string {
	if strings.TrimSpace(r.Value) == "" {
		return "—"
	}
	return r.Value
}

func (r ChartRow) SeriesClass() string {
	if r.Series == 2 {
		return "chart-series-2"
	}
	return "chart-series-1"
}

type ChartCard struct {
	ID     string
	Title  string
	Sub    string
	Kind   string
	Rows   []ChartRow
	Unit   string
	Window string
	Norm   string
	Note   string

	Scale *Scale
}

type Scale struct {
	Warn, Bad string
	owner     string
}

func NewScale(warn, bad float64, owner string) *Scale {
	if strings.TrimSpace(owner) == "" || (warn <= 0 && bad <= 0) {
		return nil
	}
	num := func(v float64) string {
		if v <= 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return &Scale{Warn: num(warn), Bad: num(bad), owner: owner}
}

func (s *Scale) Owner() string { return s.owner }

func (c ChartCard) KindName() string {
	if c.Kind == "band" {
		return "band"
	}
	return "spark"
}

func (c ChartCard) WindowName() string {
	switch c.Window {
	case "24h", "7d":
		return c.Window
	}
	return "2h"
}

func (c ChartCard) UnitName() string {
	switch c.Unit {
	case "bits", "ms", "percent", "rate":
		return c.Unit
	}
	return ""
}

func (c ChartCard) RowNames() string {
	names := make([]string, 0, len(c.Rows))
	for _, r := range c.ShownRows() {
		names = append(names, r.Name)
	}
	return strings.Join(names, ",")
}

func (c ChartCard) ShownRows() []ChartRow {
	out := make([]ChartRow, 0, len(c.Rows))
	for _, r := range c.Rows {
		if len(out) == MaxChartRows {
			break
		}
		if validRowName(r.Name) {
			out = append(out, r)
		}
	}
	return out
}

const MaxChartRows = 4

func validRowName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

type StatusLine struct {
	ID     string
	Judged Judgment
	Text   string
	Advice string
	Row    string
	Warn   string
	Bad    string

	Alive string

	TextOK, TextWarn, TextBad, TextUnknown, TextDown           string
	AdviceOK, AdviceWarn, AdviceBad, AdviceUnknown, AdviceDown string
}

func (s StatusLine) RowNames() string {
	if validRowName(s.Alive) {
		return s.Row + "," + s.Alive
	}
	return s.Row
}

func (s StatusLine) AliveName() string {
	if validRowName(s.Alive) {
		return s.Alive
	}
	return ""
}

func (s StatusLine) LevelName() string {
	if l := s.Judged.Level(); l != None {
		return string(l)
	}
	return "unknown"
}

func (s StatusLine) Live() bool {
	return validRowName(s.Row) && (s.Warn != "" || s.Bad != "")
}

type WindowChips struct {
	Current string
}

type Chip struct {
	Key     string
	Label   string
	Pressed bool
}

func (w WindowChips) Label() string {
	for _, c := range w.Chips() {
		if c.Pressed {
			return c.Label
		}
	}
	return ""
}

func (w WindowChips) Chips() []Chip {
	cur := ChartCard{Window: w.Current}.WindowName()
	all := []Chip{{Key: "2h", Label: "2 часа"}, {Key: "24h", Label: "24 часа"}, {Key: "7d", Label: "7 дней"}}
	for i := range all {
		all[i].Pressed = all[i].Key == cur
	}
	return all
}

type ChartPanel struct{}

type ChartTip struct{}

func (ChartTip) Slots() []int { return make([]int, MaxChartRows) }

type ChartGrid struct {
	Cards []ChartCard

	Wide bool
}

func (g ChartGrid) Class() string {
	if g.Wide {
		return "chart-grid chart-grid-wide"
	}
	return "chart-grid"
}

type StatusGrid struct{ Lines []StatusLine }

type MetricGrid struct{ Metrics []Metric }

type LinkCard struct {
	Title   string
	URL     string
	Metrics []Metric
	Note    string
}

type CardGrid struct{ Cards []LinkCard }

type Fact struct {
	Label  string
	Value  string
	Note   string
	Judged Judgment
}

func (f Fact) Shown() string {
	if strings.TrimSpace(f.Value) == "" {
		return "неизвестно"
	}
	return f.Value
}

func (f Fact) Class() string {
	if l := f.Judged.Level(); l != None {
		return "fact fact-" + string(l)
	}
	return "fact"
}

type StepperItem struct {
	Key   string
	Title string
	State string
	URL   string
}

type Stepper struct {
	Items   []StepperItem
	Current int
	Total   int
}

func (s StepperItem) Class() string {
	switch s.State {
	case "done", "current", "next", "todo":
		return "step step-" + s.State
	}
	return "step"
}

type ChoiceOption struct {
	Value   string
	Label   string
	Hint    string
	Facts   []string
	Checked bool

	Reveals string
}

type Choice struct {
	Name    string
	Options []ChoiceOption
}

func (c Choice) ID(o ChoiceOption) string { return c.Name + "-" + o.Value }

type Facts struct {
	Title string
	URL   string
	Items []Fact
}

func Plural(n int, one, few, many string) string {
	word := many
	switch {
	case n%10 == 1 && n%100 != 11:
		word = one
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		word = few
	}
	return strconv.Itoa(n) + " " + word
}
