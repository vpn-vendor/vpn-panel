package system

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/oswindow"
)

type Report struct {
	Status hostcaps.Status

	AgentDown bool

	Release oswindow.Release

	SupportUntil time.Time

	Stale []settings.Section
}

var distroInfo = func() ([]byte, error) { return os.ReadFile(oswindow.DistroInfoPath) }

func (s *Service) Report(now time.Time) Report {
	st, err := s.Passport()
	var r Report
	if err != nil {
		r.AgentDown = true
		return r
	}
	r.Status = st
	codename := st.Value("os.codename")
	if rel, ok := oswindow.Find(codename); ok {
		r.Release = rel
	}
	if raw, err := distroInfo(); err == nil && codename != "" {
		if eol, ok := oswindow.EOL(raw, codename); ok {
			r.SupportUntil = eol
		}
	}
	r.Stale = staleSections(st, settings.Get(SettingApplied), now)
	return r
}

func staleSections(st hostcaps.Status, appliedRaw string, now time.Time) []settings.Section {
	if st.TakenAt == "" || st.Probing || appliedRaw == "" {
		return nil
	}
	taken, err := time.Parse(time.RFC3339, st.TakenAt)
	if err != nil || now.Sub(taken) < 2*ReconcileEvery {
		return nil
	}
	applied := map[string]string{}
	if json.Unmarshal([]byte(appliedRaw), &applied) != nil {
		return nil
	}
	var out []settings.Section
	for sec, have := range applied {
		if hostcaps.SectionDigest(st.Facts, sec) != have {
			out = append(out, settings.Section(sec))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func Blocking(facts []hostcaps.Fact, consumer string) []hostcaps.Fact {
	var out []hostcaps.Fact
	for _, f := range facts {
		if f.Class != hostcaps.ClassGuard || f.Answer != hostcaps.No {
			continue
		}
		for _, c := range f.Consumers {
			if c == consumer {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func (s *Service) Refusal(consumer string) string {
	st, err := s.Passport()
	if err != nil {
		return ""
	}
	return RefusalText(Blocking(st.Facts, consumer), consumer)
}

func RefusalText(blocking []hostcaps.Fact, consumer string) string {
	if len(blocking) == 0 {
		return ""
	}
	parts := make([]string, 0, len(blocking))
	for _, f := range blocking {
		parts = append(parts, f.Missing)
	}
	return "Раздел «" + settings.Section(consumer).Title() + "» применить нельзя. " + strings.Join(parts, " ")
}
