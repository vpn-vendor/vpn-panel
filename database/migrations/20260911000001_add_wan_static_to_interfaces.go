package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260911000001AddWanStaticToInterfaces struct{}

func (r *M20260911000001AddWanStaticToInterfaces) Signature() string {
	return "20260911000001_add_wan_static_to_interfaces"
}

func (r *M20260911000001AddWanStaticToInterfaces) Up() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("interfaces", "ipv4_gateway") {
			table.String("ipv4_gateway").Default("")
		}
		if !facades.Schema().HasColumn("interfaces", "ipv4_dns") {
			table.String("ipv4_dns").Default("")
		}
	})
}

func (r *M20260911000001AddWanStaticToInterfaces) Down() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("interfaces", "ipv4_gateway") {
			table.DropColumn("ipv4_gateway")
		}
		if facades.Schema().HasColumn("interfaces", "ipv4_dns") {
			table.DropColumn("ipv4_dns")
		}
	})
}
