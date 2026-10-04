package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260929000001AddTunnelSessionToVpnChecks struct{}

func (r *M20260929000001AddTunnelSessionToVpnChecks) Signature() string {
	return "20260929000001_add_tunnel_session_to_vpn_checks"
}

func (r *M20260929000001AddTunnelSessionToVpnChecks) Up() error {
	return facades.Schema().Table("vpn_checks", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("vpn_checks", "tunnel_profile") {
			table.String("tunnel_profile", 64).Default("")
		}
		if !facades.Schema().HasColumn("vpn_checks", "tunnel_mode") {
			table.String("tunnel_mode", 16).Default("")
		}
		if !facades.Schema().HasColumn("vpn_checks", "tunnel_session") {
			table.BigInteger("tunnel_session").Default(0)
		}
	})
}

func (r *M20260929000001AddTunnelSessionToVpnChecks) Down() error {
	return facades.Schema().Table("vpn_checks", func(table schema.Blueprint) {
		for _, c := range []string{"tunnel_session", "tunnel_mode", "tunnel_profile"} {
			if facades.Schema().HasColumn("vpn_checks", c) {
				table.DropColumn(c)
			}
		}
	})
}
