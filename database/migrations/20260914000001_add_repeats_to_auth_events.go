package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260914000001AddRepeatsToAuthEvents struct{}

func (r *M20260914000001AddRepeatsToAuthEvents) Signature() string {
	return "20260914000001_add_repeats_to_auth_events"
}

func (r *M20260914000001AddRepeatsToAuthEvents) Up() error {
	return facades.Schema().Table("auth_events", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("auth_events", "repeat_count") {
			table.Integer("repeat_count").Default(0)
		}
		if !facades.Schema().HasColumn("auth_events", "last_at") {
			table.DateTimeTz("last_at").Nullable()
		}
	})
}

func (r *M20260914000001AddRepeatsToAuthEvents) Down() error {
	return facades.Schema().Table("auth_events", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("auth_events", "last_at") {
			table.DropColumn("last_at")
		}
		if facades.Schema().HasColumn("auth_events", "repeat_count") {
			table.DropColumn("repeat_count")
		}
	})
}
