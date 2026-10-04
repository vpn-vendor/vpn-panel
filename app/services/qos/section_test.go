package qos

import "testing"

func TestValidateSection(t *testing.T) {
	for _, ok := range []Section{
		{Enabled: true, DownKbit: 100_000, UpKbit: 20_000},
		{Enabled: false},
		{Enabled: false, DownKbit: 50_000, UpKbit: 10_000},
	} {
		if errs := ValidateSection(ok); len(errs) > 0 {
			t.Errorf("%+v отвергнут: %v", ok, errs.Err())
		}
	}
	for _, c := range []struct {
		v    Section
		path string
	}{
		{Section{Enabled: true, UpKbit: 20_000}, "down_kbit"},
		{Section{Enabled: false, DownKbit: 10}, "down_kbit"},
		{Section{Enabled: true, DownKbit: 100_000, UpKbit: 20_000_000}, "up_kbit"},
	} {
		if !ValidateSection(c.v).Has(c.path) {
			t.Errorf("%+v: нет ошибки поля %q", c.v, c.path)
		}
	}
}
