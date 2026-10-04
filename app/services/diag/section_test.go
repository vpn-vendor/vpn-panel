package diag

import (
	"strings"
	"testing"
)

func TestValidateSection(t *testing.T) {
	if errs := ValidateSection(Section{WindowMaxHours: 24}); len(errs) > 0 {
		t.Fatal(errs.Err())
	}
	for _, h := range []int{0, 25} {
		if !ValidateSection(Section{WindowMaxHours: h}).Has("window_max_hours") {
			t.Errorf("предел окна %d принят", h)
		}
	}
}

func TestValidateLabelsSection(t *testing.T) {
	good := LabelsSection{Labels: []SectionLabel{
		{MAC: "52:54:00:12:34:21", Label: "ПК Ирины", Location: "бухгалтерия", Owner: "Ирина", Note: "", PublicLabel: "ПК Ирины, бухгалтерия"},
	}}
	if errs := ValidateLabelsSection(good); len(errs) > 0 {
		t.Fatalf("годный раздел отвергнут: %v", errs.Err())
	}
	for _, c := range []struct {
		name string
		edit func(*LabelsSection)
		path string
	}{
		{"MAC", func(s *LabelsSection) { s.Labels[0].MAC = "52:54:00:12:34:2A" }, "labels[0].mac"},
		{"две подписи", func(s *LabelsSection) { s.Labels = append(s.Labels, s.Labels[0]) }, "labels[52:54:00:12:34:21].mac"},
		{"знак вне списка", func(s *LabelsSection) { s.Labels[0].Owner = "<b>" }, "labels[52:54:00:12:34:21].owner"},
		{"текст не в обычном виде", func(s *LabelsSection) { s.Labels[0].Location = "бухгалтерия  угол" }, "labels[52:54:00:12:34:21].location"},
		{"длинная заметка", func(s *LabelsSection) { s.Labels[0].Note = strings.Repeat("я", MaxNote+1) }, "labels[52:54:00:12:34:21].note"},
	} {
		v := LabelsSection{Labels: append([]SectionLabel(nil), good.Labels...)}
		c.edit(&v)
		if !ValidateLabelsSection(v).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateLabelsSection(v).Err())
		}
	}
}
