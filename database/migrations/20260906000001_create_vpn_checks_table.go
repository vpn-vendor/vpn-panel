package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260906000001CreateVpnChecksTable struct{}

func (r *M20260906000001CreateVpnChecksTable) Signature() string {
	return "20260906000001_create_vpn_checks_table"
}

func (r *M20260906000001CreateVpnChecksTable) Up() error {
	if facades.Schema().HasTable("vpn_checks") {
		return nil
	}
	return facades.Schema().Create("vpn_checks", func(table schema.Blueprint) {
		table.ID()
		table.String("mode").Default("quick")
		table.Text("report")
		table.DateTimeTz("created_at").UseCurrent()
	})
}

func (r *M20260906000001CreateVpnChecksTable) Down() error {
	return facades.Schema().DropIfExists("vpn_checks")
}
