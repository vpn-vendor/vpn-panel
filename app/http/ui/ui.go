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
	Icon     string
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
	case "secondary", "danger", "ghost", "danger-outline":
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

	Icon string
	Hue  string

	CopyID string
}

func (m Metric) Class() string {
	c := "metric"
	if l := m.Judged.Level(); l != None {
		c += " metric-" + string(l)
	}
	if m.Icon != "" {
		c += " metric-has-icon"
	}
	return c
}

type ChartRow struct {
	Name   string
	Label  string
	Value  string
	Series int
	Tone   Tone
}

func (r ChartRow) ToneName() string {
	if r.Tone != "" {
		return string(r.Tone)
	}
	if r.Series == 2 {
		return string(ToneTraffic2)
	}
	return string(ToneTraffic)
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

	Span int

	Tag *Tag

	Follow bool

	Chips *WindowChips

	Stub string
}

func (c ChartCard) SpanAttr() string {
	if c.Span <= 0 {
		return ""
	}
	return strconv.Itoa(c.Span)
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
	switch c.Kind {
	case "band", "area", "tile":
		return c.Kind
	}
	return "spark"
}

func (c ChartCard) WindowName() string {
	switch c.Window {
	case "2h", "24h", "7d":
		return c.Window
	}
	return "live"
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

	Bare bool
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
	all := []Chip{{Key: "live", Label: "Живое · 15 мин"}, {Key: "2h", Label: "2 часа"}, {Key: "24h", Label: "24 часа"}, {Key: "7d", Label: "7 дней"}}
	for i := range all {
		all[i].Pressed = all[i].Key == cur
	}
	return all
}

type ChartPanel struct{}

func (ChartPanel) Chips() WindowChips { return WindowChips{Bare: true} }

type ChartTip struct{}

func (ChartTip) Slots() []int { return make([]int, MaxChartRows) }

type ChartGrid struct {
	Cards []ChartCard

	Wide  bool
	Tight bool
}

func (g ChartGrid) Class() string {
	switch {
	case g.Wide:
		return "chart-grid chart-grid-wide"
	case g.Tight:
		return "chart-grid chart-grid-tight"
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

	Tag  *Tag
	Mark *ProtoMark

	Stub string
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
	Row     bool
	Options []ChoiceOption
}

func (c Choice) ID(o ChoiceOption) string { return c.Name + "-" + o.Value }

type Facts struct {
	Tiles bool
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

type Tag struct {
	Text   string
	Judged Judgment
}

func (t Tag) Class() string {
	if l := t.Judged.Level(); l != None {
		return "tag tag-" + string(l)
	}
	return "tag"
}

type ChoiceCardOption struct {
	Value    string
	Label    string
	Meta     string
	Hint     string
	Tags     []Tag
	Checked  bool
	Disabled bool

	Tone   string
	Points []Point
	Icon   string
}

type Point struct {
	Kind string
	Text string
}

func (p Point) Sign() string {
	switch p.Kind {
	case "plus":
		return "+"
	case "minus":
		return "−"
	}
	return "·"
}

type ChoiceCards struct {
	Trailing bool
	Name     string
	Legend   string
	Form     string
	Options  []ChoiceCardOption
}

func (c ChoiceCards) ID(o ChoiceCardOption) string { return c.Name + "-" + o.Value }

type HeroStatus struct {
	Title   string
	Text    string
	Judged  Judgment
	Metrics []Metric
	Tags    []Tag
	Ring    *Ring

	Icon string
}

type Ring struct{ Done, Total int }

func (r Ring) Percent() int {
	if r.Total <= 0 || r.Done <= 0 {
		return 0
	}
	if r.Done >= r.Total {
		return 100
	}
	return r.Done * 100 / r.Total
}

func (h HeroStatus) Class() string {
	if l := h.Judged.Level(); l != None {
		return "hero hero-" + string(l)
	}
	return "hero"
}

type SwitchRow struct {
	ID       string
	Name     string
	Label    string
	Text     string
	Checked  bool
	Disabled bool
	Value    string
	Tag      Tag
	OnWord   string
	OffWord  string
}

func (s SwitchRow) FormValue() string {
	if s.Value == "" {
		return "1"
	}
	return s.Value
}

func (s SwitchRow) OnText() string {
	if s.OnWord == "" {
		return "включено"
	}
	return s.OnWord
}

func (s SwitchRow) OffText() string {
	if s.OffWord == "" {
		return "выключено"
	}
	return s.OffWord
}

type UsageBar struct {
	Label   string
	Value   string
	Of      string
	Percent int
	Note    string
	Judged  Judgment
}

func (u UsageBar) Step() int {
	p := u.Percent
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return (p + 2) / 5 * 5
}

func (u UsageBar) Class() string {
	if l := u.Judged.Level(); l != None {
		return "usage usage-" + string(l)
	}
	return "usage"
}

type PageLink struct {
	URL       string
	Label     string
	Icon      string
	Secondary bool
}

type ActionForm struct {
	Action   string
	CSRF     string
	Hidden   map[string]string
	Button   Button
	Question string
}

type ItemCard struct {
	Icon    string
	Title   string
	Tags    []Tag
	Meta    []string
	Note    string
	Bar     *UsageBar
	Actions []ActionForm
	Muted   bool
	Current bool
}

func (c ItemCard) Class() string {
	switch {
	case c.Muted:
		return "item-card item-muted"
	case c.Current:
		return "item-card item-current"
	}
	return "item-card"
}

type ItemGrid struct {
	Items []ItemCard
	List  bool
	Tight bool
	Cards bool
}

type FilterBar struct {
	ID      string
	Filters []TimelineFilter
}

type TimelineEvent struct {
	Kind   string
	Tag    Tag
	Time   string
	Title  string
	Text   string
	Extra  string
	Judged Judgment
}

func (e TimelineEvent) Class() string {
	if l := e.Judged.Level(); l != None {
		return "tl-event tl-" + string(l)
	}
	return "tl-event"
}

type TimelineDay struct {
	Title  string
	Events []TimelineEvent
}

type Timeline struct {
	ID      string
	Filters []TimelineFilter
	Days    []TimelineDay
	Empty   string
}

type TimelineFilter struct {
	Kind  string
	Label string
}

type ProtoMark struct {
	Mono  string
	Label string
	Tone  int
}

func (m ProtoMark) Class() string {
	if m.Tone >= 1 && m.Tone <= 2 {
		return "proto-mark proto-tone-" + strconv.Itoa(m.Tone)
	}
	return "proto-mark"
}

type PathNode struct {
	Sub   string
	State string

	Mark string
}

func (n PathNode) MarkIcon() string {
	switch n.Mark {
	case "ok":
		return "check"
	case "error":
		return "close"
	case "add":
		return "plus"
	}
	return "warning"
}

func (n PathNode) Class() string {
	if n.State == "" {
		return "tp-node"
	}
	return "tp-node tp-" + n.State
}

type TrafficPath struct {
	Aria         string
	Gateway      PathNode
	Server       PathNode
	Exit         string
	Link         string
	LinkTag      Tag
	Provider     string
	ProviderWarn bool
}

func (p TrafficPath) PipeClass() string { return "tp-pipe tp-pipe-" + p.Link }

func (p TrafficPath) PipeIcon() string {
	switch p.Link {
	case "broken":
		return "close"
	case "open":
		return "eye"
	}
	return "lock"
}

type ProfileFact struct {
	Label  string
	Value  string
	CopyID string
}

type ProfileCard struct {
	Form      string
	Name      string
	Value     string
	Checked   bool
	Current   bool
	Title     string
	Mark      ProtoMark
	Protocol  string
	State     Tag
	Live      string
	Facts     []ProfileFact
	Tags      []Tag
	PickLabel string
	Delete    *ActionForm

	DeleteNote string

	Fresh bool
}

func (c ProfileCard) ID() string { return c.Name + "-" + c.Value }

type UploadKind struct {
	Mark ProtoMark
	Ext  string
}

type UploadZone struct {
	ID        string
	Action    string
	CSRF      string
	FileName  string
	Accept    string
	Title     string
	Text      string
	Kinds     []UploadKind
	NameField Field
	Button    Button
}

type GuideStep struct {
	Title string
	Text  string
}

type ProfileGrid struct {
	Cards  []ProfileCard
	Upload *UploadZone
	Steps  []GuideStep
}

type CheckStep struct {
	State  string
	Title  string
	Text   string
	Link   *PageLink
	Action *ActionForm
}

func (s CheckStep) Class() string { return "cl-step cl-" + s.State }

func (s CheckStep) Current() bool { return s.State == "current" }

type Checklist struct {
	ID    string
	Title string
	Text  string
	Steps []CheckStep

	View string
}

func (c Checklist) CurrentStep() CheckStep {
	for _, s := range c.Steps {
		if s.Current() {
			return s
		}
	}
	return CheckStep{}
}

func ViewOf(cookie string) string {
	switch cookie {
	case "bar", "hidden":
		return cookie
	}
	return "full"
}

func (c Checklist) DoneCount() int {
	n := 0
	for _, s := range c.Steps {
		if s.State == "done" {
			n++
		}
	}
	return n
}

func NewChecklist(id, title, text string, steps []CheckStep, done []bool) *Checklist {
	c := &Checklist{ID: id, Title: title, Text: text, View: "full"}
	current := false
	for i, s := range steps {
		switch {
		case done[i]:
			s.State = "done"
		case !current:
			s.State, current = "current", true
		default:
			s.State = "todo"
		}
		c.Steps = append(c.Steps, s)
	}
	if !current {
		return nil
	}
	return c
}
