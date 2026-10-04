package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260908000001AddProtocolToVpnProfiles struct{}

func (r *M20260908000001AddProtocolToVpnProfiles) Signature() string {
	return "20260908000001_add_protocol_to_vpn_profiles"
}

func (r *M20260908000001AddProtocolToVpnProfiles) Up() error {
	if facades.Schema().HasColumn("vpn_profiles", "protocol") {
		return nil
	}
	return facades.Schema().Table("vpn_profiles", func(table schema.Blueprint) {
		table.String("protocol").Default("wireguard")
		table.String("transport").Default("udp")
	})
}

func (r *M20260908000001AddProtocolToVpnProfiles) Down() error {
	if !facades.Schema().HasColumn("vpn_profiles", "protocol") {
		return nil
	}
	return facades.Schema().Table("vpn_profiles", func(table schema.Blueprint) {
		table.DropColumn("protocol", "transport")
	})
}
