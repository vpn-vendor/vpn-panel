package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260918000001CreateBootsTable struct{}

func (r *M20260918000001CreateBootsTable) Signature() string {
	return "20260918000001_create_boots_table"
}

func (r *M20260918000001CreateBootsTable) Up() error {
	if facades.Schema().HasTable("boots") {
		return nil
	}
	return facades.Schema().Create("boots", func(table schema.Blueprint) {
		table.ID()
		table.String("boot_id")
		table.DateTimeTz("booted_at")
		table.DateTimeTz("first_start_at")
		table.DateTimeTz("last_start_at")
		table.Integer("panel_starts").Default(1)
		table.DateTimeTz("seen_at")
		table.Boolean("clean_stop").Default(false)
		table.Unique("boot_id")
		table.Index("booted_at")
	})
}

func (r *M20260918000001CreateBootsTable) Down() error {
	return facades.Schema().DropIfExists("boots")
}
