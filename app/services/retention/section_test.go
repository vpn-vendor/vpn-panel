package retention

import "testing"

func TestValidateSection(t *testing.T) {
	good := Section{JournalDays: JournalDaysDefault, ForgetDays: ForgetDaysDefault, TrustDays: TrustKeepDaysDefault}
	if errs := ValidateSection(good); len(errs) > 0 {
		t.Fatal(errs.Err())
	}
	bad := Section{JournalDays: JournalDaysMin - 1, ForgetDays: ForgetDaysMax + 1, TrustDays: 0}
	errs := ValidateSection(bad)
	for _, p := range []string{"journal_days", "devices_forget_days", "trust_keep_days"} {
		if !errs.Has(p) {
			t.Errorf("нет ошибки поля %q: %v", p, errs.Err())
		}
	}
}
