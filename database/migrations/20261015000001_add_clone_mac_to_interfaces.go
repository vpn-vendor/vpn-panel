package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20261015000001AddCloneMacToInterfaces struct{}

func (r *M20261015000001AddCloneMacToInterfaces) Signature() string {
	return "20261015000001_add_clone_mac_to_interfaces"
}

func (r *M20261015000001AddCloneMacToInterfaces) Up() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("interfaces", "clone_mac") {
			table.String("clone_mac", 17).Default("")
		}
	})
}

func (r *M20261015000001AddCloneMacToInterfaces) Down() error {
	return facades.Schema().Table("interfaces", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("interfaces", "clone_mac") {
			table.DropColumn("clone_mac")
		}
	})
}
