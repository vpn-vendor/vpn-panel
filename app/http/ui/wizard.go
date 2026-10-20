package ui

import "strconv"

type WizardPhase struct {
	Title  string
	State  string
	Number int
	Last   bool
}

func (p WizardPhase) Class() string {
	switch p.State {
	case "done", "current":
		return "wz-ph wz-ph-" + p.State
	}
	return "wz-ph"
}

type WizardPhases struct {
	Items []WizardPhase
	Where string
}

type WizardAction struct {
	Label string
	Form  string
	URL   string
}

type WizardFoot struct {
	Where   string
	Back    string
	Skip    *WizardAction
	Extra   *WizardAction
	Primary WizardAction
}

type RearPort struct {
	Name       string
	Speed      string
	SpeedLevel string
	Link       bool
	Provider   bool
	Board      bool
	X, Y       int
	W, H       int
	CY         int
	LineX      int
	BoxY       int
}

func (p RearPort) BracketY() int { return p.Y - 8 }
func (p RearPort) PcbY() int     { return p.Y - 12 }
func (p RearPort) LabelY() int   { return p.Y + 3 }

func (p RearPort) FrameX() int { return p.X - 3 }
func (p RearPort) FrameY() int { return p.Y - 3 }
func (p RearPort) FrameW() int { return p.W + 6 }
func (p RearPort) FrameH() int { return p.H + 6 }
func (p RearPort) Y5() int     { return p.Y + 5 }
func (p RearPort) Ym2() int    { return p.Y - 2 }
func (p RearPort) X2() int     { return p.X + 2 }
func (p RearPort) LedW() int   { return p.W * 22 / 100 }
func (p RearPort) LedRX() int  { return p.X + p.W - 2 - p.LedW() }
func (p RearPort) MidX() int   { return p.X + p.W/2 }
func (p RearPort) BelowY() int { return p.Y + p.H + 14 }

func (p RearPort) Mouth() string {
	l, r, t, b, c := p.X+3, p.X+p.W-3, p.Y+3, p.Y+p.H-3, p.X+p.W/2
	n := strconv.Itoa
	return "M" + n(l) + " " + n(t) + " H" + n(r) + " V" + n(b-6) + " H" + n(c+7) + " V" + n(b) + " H" + n(c-7) + " V" + n(b-6) + " H" + n(l) + " Z"
}

func (p RearPort) ContactW() string {
	return strconv.FormatFloat(float64(p.W-12)/8-1.2, 'f', 1, 64)
}
func (p RearPort) Contacts() []string {
	out := make([]string, 8)
	for i := range out {
		out[i] = strconv.FormatFloat(float64(p.X+6)+float64(i)*float64(p.W-12)/8, 'f', 1, 64)
	}
	return out
}

func (p RearPort) RingX() int { return p.X - 10 }
func (p RearPort) RingY() int { return p.Y - 8 }
func (p RearPort) RingW() int { return p.W + 20 }
func (p RearPort) RingH() int { return p.H + 16 }

func (p RearPort) SpeedClass() string {
	switch p.SpeedLevel {
	case "fast":
		return "pr-speed pr-fast"
	case "slow":
		return "pr-speed pr-slow"
	}
	return "pr-speed"
}

type RearWant struct {
	RingY, TextY int
}

func (w RearWant) MidY() int { return w.RingY + 20 }
func (w RearWant) BoxY() int { return w.RingY + 20 - 26 }

type PCRear struct {
	Prefix string
	Plain  []int
	Ports  []RearPort

	Missing *RearWant

	Cable      string
	PlugX      int
	PlugY      int
	CableLabel int

	Guess string
}

type WizardNote struct {
	Key   string
	Label string
	Level Level
	Title string
	Text  string
}

type PortAdvice struct {
	Single  *WizardNote
	Options []WizardNote
}

func (a WizardNote) Class() string {
	switch a.Level {
	case OK, Warn:
		return "wz-note wz-note-" + string(a.Level)
	}
	return "wz-note wz-note-info"
}

func (a WizardNote) Mark() string {
	switch a.Level {
	case OK:
		return "✓"
	case Warn:
		return "!"
	}
	return "i"
}

type Contract struct {
	Caption bool
}

type WaitCheck struct {
	Key   string `json:"key"`
	State string `json:"state"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

func (c WaitCheck) Mark() string {
	switch c.State {
	case "done":
		return "✓"
	case "fail":
		return "!"
	}
	return ""
}

type Wait struct {
	State  string      `json:"state"`
	Left   int         `json:"left"`
	Dash   int         `json:"dash"`
	Big    string      `json:"big"`
	Small  string      `json:"small"`
	Title  string      `json:"title"`
	Lead   string      `json:"lead"`
	Checks []WaitCheck `json:"checks"`
}

func (w Wait) Tone() string {
	switch w.State {
	case "confirmed":
		return "ok"
	case "rolledback":
		return "warn"
	}
	return "run"
}

type TakeoverList struct {
	Name  string
	Items []TakeoverItem
}

type TakeoverItem struct {
	ID      string
	Title   string
	Found   string
	Checked bool
	Locked  bool
}

func (l TakeoverList) Field(it TakeoverItem) string { return l.Name + "_" + it.ID }
