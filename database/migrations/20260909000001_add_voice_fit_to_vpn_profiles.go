package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260909000001AddVoiceFitToVpnProfiles struct{}

func (r *M20260909000001AddVoiceFitToVpnProfiles) Signature() string {
	return "20260909000001_add_voice_fit_to_vpn_profiles"
}

func (r *M20260909000001AddVoiceFitToVpnProfiles) Up() error {
	if facades.Schema().HasColumn("vpn_profiles", "voice_fit") {
		return nil
	}
	return facades.Schema().Table("vpn_profiles", func(table schema.Blueprint) {
		table.Boolean("voice_fit").Default(true)
	})
}

func (r *M20260909000001AddVoiceFitToVpnProfiles) Down() error {
	if !facades.Schema().HasColumn("vpn_profiles", "voice_fit") {
		return nil
	}
	return facades.Schema().Table("vpn_profiles", func(table schema.Blueprint) {
		table.DropColumn("voice_fit")
	})
}
