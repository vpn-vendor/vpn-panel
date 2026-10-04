package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260916000002AddIdentifyRequestToDevices struct{}

func (r *M20260916000002AddIdentifyRequestToDevices) Signature() string {
	return "20260916000002_add_identify_request_to_devices"
}

func (r *M20260916000002AddIdentifyRequestToDevices) Up() error {
	return facades.Schema().Table("devices", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("devices", "identify_requested_at") {
			table.DateTimeTz("identify_requested_at").Nullable()
		}
		if !facades.Schema().HasColumn("devices", "identify_note") {
			table.String("identify_note", 120).Default("")
		}
		if !facades.Schema().HasColumn("devices", "identify_ip") {
			table.String("identify_ip", 45).Default("")
		}
		if !facades.Schema().HasColumn("devices", "identify_segment") {
			table.String("identify_segment", 32).Default("")
		}
		if !facades.Schema().HasColumn("devices", "identify_count") {
			table.Integer("identify_count").Default(0)
		}
	})
}

func (r *M20260916000002AddIdentifyRequestToDevices) Down() error {
	return facades.Schema().Table("devices", func(table schema.Blueprint) {
		for _, col := range []string{"identify_count", "identify_segment", "identify_ip", "identify_note", "identify_requested_at"} {
			if facades.Schema().HasColumn("devices", col) {
				table.DropColumn(col)
			}
		}
	})
}
