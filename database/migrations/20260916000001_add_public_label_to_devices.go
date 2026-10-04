package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260916000001AddPublicLabelToDevices struct{}

func (r *M20260916000001AddPublicLabelToDevices) Signature() string {
	return "20260916000001_add_public_label_to_devices"
}

func (r *M20260916000001AddPublicLabelToDevices) Up() error {
	return facades.Schema().Table("devices", func(table schema.Blueprint) {
		if !facades.Schema().HasColumn("devices", "public_label") {
			table.String("public_label", 120).Default("")
		}
		if !facades.Schema().HasColumn("devices", "label_reviewed_at") {
			table.DateTimeTz("label_reviewed_at").Nullable()
		}
	})
}

func (r *M20260916000001AddPublicLabelToDevices) Down() error {
	return facades.Schema().Table("devices", func(table schema.Blueprint) {
		if facades.Schema().HasColumn("devices", "label_reviewed_at") {
			table.DropColumn("label_reviewed_at")
		}
		if facades.Schema().HasColumn("devices", "public_label") {
			table.DropColumn("public_label")
		}
	})
}
