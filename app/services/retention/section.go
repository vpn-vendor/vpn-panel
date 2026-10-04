package retention

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type Section struct {
	JournalDays int  `json:"journal_days" setting:"retention.journal_days"`
	ForgetDays  int  `json:"devices_forget_days" setting:"retention.devices_forget_days"`
	TrustDays   int  `json:"trust_keep_days" setting:"retention.trust_keep_days"`
	SyslogCap   bool `json:"syslog_cap" setting:"retention.syslog_cap"`
}

func ReadSection() (Section, error) {
	st := Load()
	return Section{JournalDays: st.JournalDays, ForgetDays: st.ForgetDays, TrustDays: st.TrustDays,
		SyslogCap: settingString(SettingSyslogCap) == "1"}, nil
}

func ValidateSection(v Section) fielderr.List {
	return validateTerms(Settings{JournalDays: v.JournalDays, ForgetDays: v.ForgetDays, TrustDays: v.TrustDays})
}

func ApplySection(cur, want Section) error { return settings.WriteChanged(cur, want) }

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}
