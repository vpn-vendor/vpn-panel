package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260905000001CreateVpnProfilesTable struct{}

func (r *M20260905000001CreateVpnProfilesTable) Signature() string {
	return "20260905000001_create_vpn_profiles_table"
}

func (r *M20260905000001CreateVpnProfilesTable) Up() error {
	if facades.Schema().HasTable("vpn_profiles") {
		return nil
	}
	return facades.Schema().Create("vpn_profiles", func(table schema.Blueprint) {
		table.ID()
		table.String("name")
		table.String("slug")
		table.String("endpoint_host").Default("")
		table.Integer("endpoint_port").Default(0)
		table.String("peer_key").Default("")
		table.String("addresses").Default("")
		table.String("allowed_ips").Default("")

		table.String("config_dns").Default("")
		table.Integer("config_mtu").Default(0)
		table.Integer("keepalive").Default(0)
		table.Boolean("full_tunnel").Default(false)
		table.DateTimeTz("created_at").UseCurrent()
		table.DateTimeTz("updated_at").UseCurrent()
		table.Unique("slug")
	})
}

func (r *M20260905000001CreateVpnProfilesTable) Down() error {
	return facades.Schema().DropIfExists("vpn_profiles")
}
