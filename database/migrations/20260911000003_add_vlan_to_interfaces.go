package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260911000003AddVlanToInterfaces struct{}

func (r *M20260911000003AddVlanToInterfaces) Signature() string {
	return "20260911000003_add_vlan_to_interfaces"
}

func (r *M20260911000003AddVlanToInterfaces) Up() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("interfaces", "vlan") {
			table.Integer("vlan").Default(0)
		}
	})
}

func (r *M20260911000003AddVlanToInterfaces) Down() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("interfaces", "vlan") {
			table.DropColumn("vlan")
		}
	})
}
