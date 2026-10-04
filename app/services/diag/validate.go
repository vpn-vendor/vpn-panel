package diag

import "github.com/vpn-vendor/vpn-panel-core/internal/usertext"

const (
	MaxLabel = 40

	MaxPublicLabel = 120
	MaxLocation    = 60
	MaxOwner       = 40
	MaxNote        = 120
)

func PreviewProposal(label, location, owner string) string {
	l, err := ValidateText(label, MaxLabel)
	if err != nil {
		return "название: " + err.Error()
	}
	loc, err := ValidateText(location, MaxLocation)
	if err != nil {
		return "где стоит: " + err.Error()
	}
	own, err := ValidateText(owner, MaxOwner)
	if err != nil {
		return "кому принадлежит: " + err.Error()
	}
	if l == "" && loc == "" && own == "" {
		return "заполните хотя бы одно поле"
	}
	return ""
}

func ValidateText(raw string, max int) (string, error) { return usertext.Validate(raw, max, "") }
