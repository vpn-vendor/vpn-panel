package auth

import "testing"

func TestValidateSection(t *testing.T) {
	good := Section{MaxUsers: 1, DeviceSlidingHours: 72, DeviceAbsoluteDays: 14, QuarantineHours: 24, CodeTTLMinutes: 10}
	if errs := ValidateSection(good); len(errs) > 0 {
		t.Fatalf("умолчания отвергнуты: %v", errs.Err())
	}
	for _, c := range []struct {
		name string
		edit func(*Section)
		path string
	}{
		{"учётных записей ноль", func(s *Section) { s.MaxUsers = 0 }, "max_users"},
		{"учётных записей много", func(s *Section) { s.MaxUsers = 51 }, "max_users"},
		{"срок доверия выше потолка", func(s *Section) { s.DeviceAbsoluteDays = 31 }, "device_absolute_days"},
		{"неактивность длиннее доверия", func(s *Section) { s.DeviceSlidingHours = 14*24 + 1 }, "device_sliding_hours"},
		{"карантин во всё доверие", func(s *Section) { s.QuarantineHours = 14 * 24 }, "quarantine_hours"},
		{"код дольше 10 минут", func(s *Section) { s.CodeTTLMinutes = 11 }, "code_ttl_minutes"},
		{"код короче 3 минут", func(s *Section) { s.CodeTTLMinutes = 2 }, "code_ttl_minutes"},
	} {
		v := good
		c.edit(&v)
		if !ValidateSection(v).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateSection(v).Err())
		}
	}
	edge := good
	edge.DeviceAbsoluteDays, edge.DeviceSlidingHours, edge.QuarantineHours = 30, 30*24, 30*24-1
	if errs := ValidateSection(edge); len(errs) > 0 {
		t.Errorf("границы включительно отвергнуты: %v", errs.Err())
	}
}
