package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260911000002AddPppoeUsernameToInterfaces struct{}

func (r *M20260911000002AddPppoeUsernameToInterfaces) Signature() string {
	return "20260911000002_add_pppoe_username_to_interfaces"
}

func (r *M20260911000002AddPppoeUsernameToInterfaces) Up() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("interfaces", "pppoe_username") {
			table.String("pppoe_username").Default("")
		}
	})
}

func (r *M20260911000002AddPppoeUsernameToInterfaces) Down() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("interfaces", "pppoe_username") {
			table.DropColumn("pppoe_username")
		}
	})
}
