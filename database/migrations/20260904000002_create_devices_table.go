package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260904000002CreateDevicesTable struct{}

func (r *M20260904000002CreateDevicesTable) Signature() string {
	return "20260904000002_create_devices_table"
}

func (r *M20260904000002CreateDevicesTable) Up() error {
	if facades.Schema().HasTable("devices") {
		return nil
	}
	return facades.Schema().Create("devices", func(table schema.Blueprint) {
		table.ID()
		table.String("mac")
		table.String("hostname").Default("")
		table.String("last_ip").Default("")
		table.String("label").Default("")
		table.String("location").Default("")
		table.String("owner").Default("")
		table.String("note").Default("")
		table.String("label_source").Default("")
		table.String("proposed_label").Default("")
		table.String("proposed_location").Default("")
		table.String("proposed_owner").Default("")
		table.String("proposed_ip").Default("")
		table.DateTimeTz("proposed_at").Nullable()
		table.Integer("lan_mbit").Default(0)
		table.Float("lan_idle_ms").Default(0)
		table.Float("lan_load_ms").Default(0)
		table.DateTimeTz("lan_tested_at").Nullable()
		table.DateTimeTz("first_seen_at").UseCurrent()
		table.DateTimeTz("last_seen_at").UseCurrent()
		table.DateTimeTz("created_at").UseCurrent()
		table.DateTimeTz("updated_at").UseCurrent()
		table.Unique("mac")
	})
}

func (r *M20260904000002CreateDevicesTable) Down() error {
	return facades.Schema().DropIfExists("devices")
}
