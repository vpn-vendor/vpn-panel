package policy

import (
	"encoding/json"
	"fmt"
)

const schemaCurrent = 1

const (
	FlagQoSOff       = "qos-off"
	FlagUpdatesPause = "updates-pause"
)

type Kind int

const (
	KillSwitch Kind = iota

	SafeMode
)

type Flag struct {
	Name string
	Kind Kind
	Why  string
}

var registry = []Flag{
	{Name: FlagQoSOff, Kind: KillSwitch,
		Why: "отключить приоритет голоса (QoS) на всех картах, если очередь душит сеть на каком-то железе"},
	{Name: FlagUpdatesPause, Kind: KillSwitch,
		Why: "приостановить автоматические обновления панели, если обновление вредит"},
}

func byName(name string) (Flag, bool) {
	for _, f := range registry {
		if f.Name == name {
			return f, true
		}
	}
	return Flag{}, false
}

func Registry() []Flag {
	out := make([]Flag, len(registry))
	copy(out, registry)
	return out
}

type Advisory struct {
	PullNow bool   `json:"pull_now"`
	Message string `json:"message"`
}

type Policy struct {
	flags    map[string]bool
	advisory Advisory
	knownBad []string
	floor    string
	ceiling  string
}

func Default() Policy { return Policy{flags: map[string]bool{}} }

func (p Policy) Bool(name string) bool { return p.flags[name] }

func (p Policy) Advisory() Advisory { return p.advisory }

func (p Policy) KnownBad() []string {
	out := make([]string, len(p.knownBad))
	copy(out, p.knownBad)
	return out
}

func (p Policy) Floor() string { return p.floor }

func (p Policy) Ceiling() string { return p.ceiling }

type wire struct {
	Schema   int                        `json:"schema"`
	Flags    map[string]json.RawMessage `json:"flags"`
	Advisory Advisory                   `json:"advisory"`
	KnownBad []string                   `json:"known_bad"`
	Floor    string                     `json:"floor"`
	Ceiling  string                     `json:"ceiling"`
}

func Parse(data []byte) (Policy, []string, error) {
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return Default(), nil, fmt.Errorf("документ политики не разобран: %w", err)
	}
	if w.Schema != schemaCurrent {
		return Default(), nil, fmt.Errorf("версия формата политики %d, ждём %d", w.Schema, schemaCurrent)
	}
	p := Policy{flags: map[string]bool{}, advisory: w.Advisory, knownBad: w.KnownBad, floor: w.Floor, ceiling: w.Ceiling}
	var warn []string
	for name, raw := range w.Flags {
		f, ok := byName(name)
		if !ok {
			warn = append(warn, "неизвестный флаг пропущен: "+name)
			continue
		}
		switch f.Kind {
		case KillSwitch, SafeMode:
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				warn = append(warn, "флаг "+name+": ждём да/нет, значение отброшено")
				continue
			}
			p.flags[name] = b
		}
	}
	return p, warn, nil
}
