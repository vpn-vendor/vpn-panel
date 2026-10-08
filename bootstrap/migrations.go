package bootstrap

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/database/migrations"
)

func Migrations() []schema.Migration {
	return []schema.Migration{
		&migrations.M20210101000001CreateJobsTable{},
		&migrations.M20260829000001CreateAuthTables{},
		&migrations.M20260830000001CreateInterfacesTable{},
		&migrations.M20260831000001CreateDhcpReservationsTable{},
		&migrations.M20260904000001SeedAppliedLans{},
		&migrations.M20260904000002CreateDevicesTable{},
		&migrations.M20260905000001CreateVpnProfilesTable{},
		&migrations.M20260906000001CreateVpnChecksTable{},
		&migrations.M20260908000001AddProtocolToVpnProfiles{},
		&migrations.M20260909000001AddVoiceFitToVpnProfiles{},
		&migrations.M20260911000001AddWanStaticToInterfaces{},
		&migrations.M20260911000002AddPppoeUsernameToInterfaces{},
		&migrations.M20260911000003AddVlanToInterfaces{},
		&migrations.M20260914000001AddRepeatsToAuthEvents{},
		&migrations.M20260916000001AddPublicLabelToDevices{},
		&migrations.M20260916000002AddIdentifyRequestToDevices{},
		&migrations.M20261008000001BackfillSetupFinished{},
		&migrations.M20260918000001CreateBootsTable{},
		&migrations.M20260927000001ForgetProductIfaces{},
		&migrations.M20260929000001AddTunnelSessionToVpnChecks{},
	}
}
