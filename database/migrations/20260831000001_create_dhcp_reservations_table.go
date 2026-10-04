package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260831000001CreateDhcpReservationsTable struct{}

func (r *M20260831000001CreateDhcpReservationsTable) Signature() string {
	return "20260831000001_create_dhcp_reservations_table"
}

func (r *M20260831000001CreateDhcpReservationsTable) Up() error {
	if facades.Schema().HasTable("dhcp_reservations") {
		return nil
	}
	return facades.Schema().Create("dhcp_reservations", func(table schema.Blueprint) {
		table.ID()
		table.String("label")
		table.String("mac")
		table.String("ip")
		table.String("subnet")
		table.DateTimeTz("created_at").UseCurrent()
		table.DateTimeTz("updated_at").UseCurrent()
		table.Unique("mac")
		table.Unique("ip")
	})
}

func (r *M20260831000001CreateDhcpReservationsTable) Down() error {
	return facades.Schema().DropIfExists("dhcp_reservations")
}
