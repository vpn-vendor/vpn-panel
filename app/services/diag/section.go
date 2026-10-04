package diag

import (
	"time"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
)

type Section struct {
	ActiveProbes   bool `json:"active_probes" setting:"diag.active_probes"`
	SelfLabel      bool `json:"self_label" setting:"diag.self_label"`
	WindowMaxHours int  `json:"window_max_hours" setting:"diag.window_max_hours"`
}

func ReadSection() (Section, error) {
	svc := New()
	st := svc.Settings()
	return Section{ActiveProbes: st.ActiveProbes, SelfLabel: st.SelfLabel, WindowMaxHours: svc.Window().MaxHours()}, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	if v.WindowMaxHours < 1 || v.WindowMaxHours > WindowMaxHrsHi {
		errs.Add("window_max_hours", "предел окна полной проверки — от 1 до %d часов", WindowMaxHrsHi)
	}
	return errs
}

type LabelsSection struct {
	Labels []SectionLabel `json:"labels" table:"devices"`
}

type SectionLabel struct {
	MAC         string `json:"mac"`
	Label       string `json:"label"`
	Location    string `json:"location"`
	Owner       string `json:"owner"`
	Note        string `json:"note"`
	PublicLabel string `json:"public_label"`
}

func ReadLabelsSection() (LabelsSection, error) {
	var rows []models.Device
	if err := facades.Orm().Query().OrderBy("id").Find(&rows); err != nil {
		return LabelsSection{}, err
	}
	out := LabelsSection{Labels: []SectionLabel{}}
	for _, r := range rows {
		if r.Label == "" && r.Location == "" && r.Owner == "" && r.Note == "" && r.PublicLabel == "" {
			continue
		}
		out.Labels = append(out.Labels, SectionLabel{MAC: r.MAC, Label: r.Label, Location: r.Location,
			Owner: r.Owner, Note: r.Note, PublicLabel: r.PublicLabel})
	}
	return out, nil
}

func ValidateLabelsSection(v LabelsSection) fielderr.List {
	var errs fielderr.List
	seen := map[string]bool{}
	for n, l := range v.Labels {
		key := ""
		if keagen.ValidMAC(l.MAC) {
			key = l.MAC
		}
		path := fielderr.Row("labels", n, key)
		switch {
		case !keagen.ValidMAC(l.MAC):
			errs.Add(fielderr.Join(path, "mac"), "неверный аппаратный адрес %q (вид a4:bb:6d:1f:22:90)", l.MAC)
		case seen[l.MAC]:
			errs.Add(fielderr.Join(path, "mac"), "у устройства %s две подписи", l.MAC)
		}
		seen[l.MAC] = true
		for _, f := range []struct {
			name, val string
			max       int
		}{
			{"label", l.Label, MaxLabel}, {"location", l.Location, MaxLocation}, {"owner", l.Owner, MaxOwner},
			{"note", l.Note, MaxNote}, {"public_label", l.PublicLabel, MaxPublicLabel},
		} {
			switch clean, err := ValidateText(f.val, f.max); {
			case err != nil:
				errs.Add(fielderr.Join(path, f.name), "%s", err.Error())
			case clean != f.val:
				errs.Add(fielderr.Join(path, f.name), "текст не в обычном виде: лишние пробелы или невидимые символы")
			}
		}
	}
	return errs
}

func ApplySection(cur, want Section) error {
	if err := settings.WriteChanged(cur, want); err != nil {
		return err
	}
	if want.WindowMaxHours != cur.WindowMaxHours {
		return New().Window().FitOpenTo(want.WindowMaxHours)
	}
	return nil
}

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}

func ApplyLabelsSection(cur, want LabelsSection) error { return applyLabels(cur, want, "admin") }

func applyLabels(cur, want LabelsSection, source string) error {
	added, changed, removed := change.Rows(cur.Labels, want.Labels, func(l SectionLabel) string { return l.MAC })
	if len(added)+len(changed)+len(removed) == 0 {
		return nil
	}
	now := time.Now()
	write := func(tx orm.Query, l SectionLabel) error {
		fields := map[string]any{"label": l.Label, "location": l.Location, "owner": l.Owner, "note": l.Note,
			"public_label": l.PublicLabel, "label_source": source, "label_reviewed_at": now, "updated_at": now}
		res, err := tx.Model(&models.Device{}).Where("mac", l.MAC).Update(fields)
		if err != nil || res.RowsAffected > 0 {
			return err
		}
		return tx.Create(&models.Device{MAC: l.MAC, Label: l.Label, Location: l.Location, Owner: l.Owner,
			Note: l.Note, PublicLabel: l.PublicLabel, LabelSource: source, LabelReviewedAt: &now,
			FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now})
	}
	return facades.Orm().Transaction(func(tx orm.Query) error {
		for _, l := range append(added, changed...) {
			if err := write(tx, l); err != nil {
				return err
			}
		}
		for _, l := range removed {
			if err := write(tx, SectionLabel{MAC: l.MAC}); err != nil {
				return err
			}
		}
		return nil
	})
}

func EditLabels(source string, edit func(*LabelsSection) error) (LabelsSection, error) {
	return change.Apply(change.Section[LabelsSection]{Read: ReadLabelsSection, Validate: ValidateLabelsSection,
		Apply: func(cur, want LabelsSection) error { return applyLabels(cur, want, source) }}, edit)
}

func labelOf(v *LabelsSection, mac string) *SectionLabel {
	for i := range v.Labels {
		if v.Labels[i].MAC == mac {
			return &v.Labels[i]
		}
	}
	v.Labels = append(v.Labels, SectionLabel{MAC: mac})
	return &v.Labels[len(v.Labels)-1]
}
