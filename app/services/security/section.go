package security

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type Section struct {
	HiddenMode bool `json:"hidden_mode" setting:"security.hidden_mode"`
	IPv6       bool `json:"ipv6" setting:"security.ipv6"`
}

func ReadSection() (Section, error) {
	st := New().Load()
	return Section(st), nil
}

func ValidateSection(Section) fielderr.List { return nil }

func ApplySection(cur, want Section) error { return settings.WriteChanged(cur, want) }

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}
