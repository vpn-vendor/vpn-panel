package system

import (
	"encoding/json"
	"errors"
	"log"
	"sort"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
)

const SettingApplied = "hostcaps.applied"

type Reapply func() error

var ErrNotNow = errors.New("раздел занят")

const backoffCap = 64

type backoff struct {
	want string
	wait int
	next int
}

type Reconciler struct {
	passport func() (hostcaps.Status, error)
	reapply  map[settings.Section]Reapply
	load     func() string
	save     func(string) error
	audit    func(section settings.Section)
	failing  map[settings.Section]*backoff
}

func NewReconciler(reapply map[settings.Section]Reapply) *Reconciler {
	return &Reconciler{
		passport: New().Passport,
		reapply:  reapply,
		load:     func() string { return settings.Get(SettingApplied) },
		save:     func(v string) error { return settings.Set(SettingApplied, v) },
		audit: func(sec settings.Section) {
			securitylog.Record(models.AuthEvent{Event: "host_reapply", Details: sec.Title(), OccurredAt: time.Now()})
		},
	}
}

func (r *Reconciler) Step() ([]settings.Section, error) {
	st, err := r.passport()
	if err != nil {
		return nil, err
	}
	if st.TakenAt == "" || st.Probing {

		return nil, nil
	}
	applied := map[string]string{}
	if raw := r.load(); raw != "" {
		_ = json.Unmarshal([]byte(raw), &applied)
	}
	sections := make([]settings.Section, 0, len(r.reapply))
	for sec := range r.reapply {
		sections = append(sections, sec)
	}
	sort.Slice(sections, func(a, b int) bool { return sections[a] < sections[b] })

	var redone []settings.Section
	changed := false
	for _, sec := range sections {
		want := hostcaps.SectionDigest(st.Facts, string(sec))
		have, seen := applied[string(sec)]
		if !seen {

			applied[string(sec)] = want
			changed = true
			continue
		}
		if have == want || r.waiting(sec, want) {
			continue
		}
		if err := r.reapply[sec](); err != nil {
			if !errors.Is(err, ErrNotNow) {
				r.failed(sec, want)
				log.Printf("vpn-panel: раздел %s не перерисован под систему: %v", sec, err)
			}
			continue
		}
		delete(r.failing, sec)
		applied[string(sec)] = want
		changed = true
		redone = append(redone, sec)
		r.audit(sec)
	}
	if changed {
		raw, _ := json.Marshal(applied)
		if err := r.save(string(raw)); err != nil {
			return redone, err
		}
	}
	return redone, nil
}

func (r *Reconciler) waiting(sec settings.Section, want string) bool {
	b := r.failing[sec]
	if b == nil || b.want != want {
		return false
	}
	if b.wait > 0 {
		b.wait--
		return true
	}
	return false
}

func (r *Reconciler) failed(sec settings.Section, want string) {
	if r.failing == nil {
		r.failing = map[settings.Section]*backoff{}
	}
	b := r.failing[sec]
	if b == nil || b.want != want {
		b = &backoff{want: want, next: 1}
		r.failing[sec] = b
	}
	b.wait = b.next
	if b.next < backoffCap {
		b.next *= 2
	}
}
