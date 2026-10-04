package metrics

import (
	"slices"
	"sort"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type Section struct {
	Master  string            `json:"master" setting:"metrics.master"`
	Sources map[string]string `json:"sources" setting:"metrics.source."`
}

var registered = map[string]bool{}

func RegisterSourceName(name string) { registered[name] = true }

func SourceNames() []string {
	var out []string
	for _, s := range Sources(&LinkSource{}, &QoSSource{}) {
		out = append(out, s.Name)
	}
	for n := range registered {
		out = append(out, n)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func adminMode(raw string) string {
	st := Parse(raw)
	if st.Mode == Paused {
		st = State{Mode: On}
	}
	return st.String()
}

func ReadSection() (Section, error) {
	sources, err := settings.Prefixed(SettingSource)
	if err != nil {
		return Section{}, err
	}
	return Section{Master: settings.Get(SettingMaster), Sources: sources}, nil
}

func ReadSectionForCopy() (Section, error) {
	v, err := ReadSection()
	if err != nil {
		return v, err
	}
	out := Section{Master: adminMode(v.Master), Sources: map[string]string{}}
	for name, raw := range v.Sources {
		out.Sources[name] = adminMode(raw)
	}
	return out, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	if !persistentMode(v.Master) {
		errs.Add("master", "общий выключатель — on, memory или off")
	}
	known := map[string]bool{}
	for _, n := range SourceNames() {
		known[n] = true
	}
	for name, mode := range v.Sources {
		path := fielderr.Join("sources", name)
		switch {
		case !known[name]:
			errs.Add(path, "неизвестный источник показателей")
		case !persistentMode(mode):
			errs.Add(path, "состояние источника — on, memory или off")
		}
	}
	return errs
}

func persistentMode(s string) bool { return s == "on" || s == "memory" || s == "off" }

func ApplySection(cur, want Section, ip string) error {
	col := Current()
	if col == nil {
		return settings.WriteChanged(cur, want)
	}
	if want.Master != cur.Master {
		if err := col.SetMaster(Parse(want.Master), ip); err != nil {
			return err
		}
	}

	names := map[string]bool{}
	for n := range cur.Sources {
		names[n] = true
	}
	for n := range want.Sources {
		names[n] = true
	}
	for name := range names {
		if want.Sources[name] != cur.Sources[name] {
			if err := col.SetSource(name, Parse(want.Sources[name]), ip); err != nil {
				return err
			}
		}
	}
	return nil
}

func Edit(ip string, edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection,
		Apply: func(cur, want Section) error { return ApplySection(cur, want, ip) }}, edit)
}
