package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260830000001CreateInterfacesTable struct{}

func (r *M20260830000001CreateInterfacesTable) Signature() string {
	return "20260830000001_create_interfaces_table"
}

func (r *M20260830000001CreateInterfacesTable) Up() error {
	if facades.Schema().HasTable("interfaces") {
		return nil
	}
	return facades.Schema().Create("interfaces", func(table schema.Blueprint) {
		table.ID()
		table.String("name")
		table.String("mac")
		table.String("role")
		table.String("ipv4_method")
		table.String("ipv4_cidr")
		table.UnsignedInteger("wan_metric").Default(100)
		table.DateTimeTz("created_at").UseCurrent()
		table.DateTimeTz("updated_at").UseCurrent()
		table.Unique("name")
	})
}

func (r *M20260830000001CreateInterfacesTable) Down() error {
	return facades.Schema().DropIfExists("interfaces")
}
