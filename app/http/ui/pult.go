package ui

import (
	"math"
	"strconv"
)

type Tone string

const (
	ToneTraffic  Tone = "s1"
	ToneTraffic2 Tone = "s2"
	ToneCPU      Tone = "cpu"
	ToneMem      Tone = "mem"
	ToneDisk     Tone = "disk"
)

func (t Tone) Class() string {
	switch t {
	case ToneTraffic2, ToneCPU, ToneMem, ToneDisk:
		return "tone-" + string(t)
	}
	return "tone-s1"
}

type Gauge struct {
	ID       string
	Title    string
	Tone     Tone
	Row      string
	Row2     string
	Unit     string
	Max      float64
	Value    float64
	Value2   float64
	Known    bool
	Note     string
	Empty    string
	Legend   []GaugeLegend
	Warn     float64
	Bad      float64
	owner    string
	LevelCSS string
}

type GaugeLegend struct {
	Label string
	Row   string
	Unit  string
	Value string
	Tone  Tone
	Faint bool
}

func (g Gauge) WithScale(warn, bad float64, owner string) Gauge {
	if owner == "" {
		return g
	}
	g.Warn, g.Bad, g.owner = warn, bad, owner
	if g.Known {
		switch {
		case bad > 0 && g.Value >= bad:
			g.LevelCSS = "error"
		case warn > 0 && g.Value >= warn:
			g.LevelCSS = "warn"
		}
	}
	return g
}

func (g Gauge) frac(v float64) float64 {
	if !g.Known || g.Max <= 0 {
		return 0
	}
	return math.Max(0, math.Min(1, v/g.Max))
}

func dash(frac float64) string {
	return strconv.FormatFloat(100*frac, 'f', 1, 64) + " 100"
}

func (g Gauge) Dash() string { return dash(g.frac(g.Value)) }

func (g Gauge) Dash2() string { return dash(g.frac(g.Value + g.Value2)) }

func (g Gauge) Shown() string {
	if !g.Known {
		return "—"
	}
	if g.Unit == "celsius" {
		return strconv.FormatFloat(math.Round(g.Value), 'f', 0, 64) + " °C"
	}
	return strconv.FormatFloat(math.Round(g.Value), 'f', 0, 64) + " %"
}

func (g Gauge) Class() string {
	c := "card gauge " + g.Tone.Class()
	if g.LevelCSS != "" {
		c += " gauge-" + g.LevelCSS
	}
	if !g.Known {
		c += " gauge-empty"
	}
	return c
}

func (g Gauge) MaxAttr() string { return strconv.FormatFloat(g.Max, 'f', -1, 64) }

func (Gauge) Num(v float64) string {
	if v <= 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

type GaugeGrid struct{ Gauges []Gauge }

type StripFact struct {
	Label  string
	Value  string
	Judged Judgment
}

func (f StripFact) Class() string {
	if l := f.Judged.Level(); l != None {
		return "strip-fact strip-fact-" + string(l)
	}
	return "strip-fact"
}

type FactStrip struct{ Items []StripFact }

type ScoreCard struct {
	Row        string
	Value      float64
	Known      bool
	Good, Poor float64
	Level      Level
	Empty      string
	Parts      []ScorePart
	Note       string
}

type ScorePart struct {
	Label string
	Row   string
	Unit  string
	Value string
}

const (
	ScoreMin = 1.0
	ScoreMax = 5.0
)

func scorePos(v float64) float64 {
	return math.Max(0, math.Min(100, (v-ScoreMin)/(ScoreMax-ScoreMin)*100))
}

func (s ScoreCard) Shown() string {
	if !s.Known {
		return "—"
	}
	return strconv.FormatFloat(math.Round(s.Value*10)/10, 'f', 1, 64)
}

func (s ScoreCard) PoorAt() string { return strconv.FormatFloat(scorePos(s.Poor), 'f', 1, 64) }
func (s ScoreCard) GoodAt() string { return strconv.FormatFloat(scorePos(s.Good), 'f', 1, 64) }

func (s ScoreCard) FairWidth() string {
	return strconv.FormatFloat(scorePos(s.Good)-scorePos(s.Poor), 'f', 1, 64)
}
func (s ScoreCard) GoodWidth() string { return strconv.FormatFloat(100-scorePos(s.Good), 'f', 1, 64) }

func (s ScoreCard) MarkAt() string {
	if !s.Known {
		return "0"
	}
	return strconv.FormatFloat(scorePos(s.Value), 'f', 1, 64)
}

func (ScoreCard) Num(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

func (s ScoreCard) Class() string {
	if !s.Known {
		return "card score score-unknown"
	}
	return "card score score-" + string(s.Level)
}

type UptimeWindow struct {
	Key     string
	Label   string
	Pct     string
	For     string
	From    string
	Cells   []string
	Down    string
	Off     string
	Partial string
	Checked bool
}

type UptimeCard struct {
	Windows []UptimeWindow
	Note    string
}

type FeedEvent struct {
	ID     uint
	Time   string
	Title  string
	Detail string
	Level  Level
}

func (e FeedEvent) Class() string {
	if e.Level == None {
		return "feed-ev feed-none"
	}
	return "feed-ev feed-" + string(e.Level)
}

type Feed struct {
	Events []FeedEvent
	After  uint
	Cap    int
}

func (f Feed) LastID() string { return strconv.FormatUint(uint64(f.After), 10) }

type PultTrio struct {
	Score  ScoreCard
	Uptime UptimeCard
	LAN    ChartCard
}

type PultWork struct {
	Tiles ChartGrid
	Feed  Feed
}
