package bootstrap

import (
	"github.com/goravel/framework/contracts/console"
	contractsfoundation "github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/foundation"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"

	"github.com/vpn-vendor/vpn-panel-core/app/console/commands"
	"github.com/vpn-vendor/vpn-panel-core/config"
	"github.com/vpn-vendor/vpn-panel-core/routes"
)

func Boot() contractsfoundation.Application {

	change.Durable = settings.Durable
	return foundation.Setup().
		WithMigrations(Migrations).
		WithCommands(func() []console.Command {
			return []console.Command{
				&commands.AuthCode{},
				&commands.AuthDesktopLogin{},
				&commands.AuthReset{},
				&commands.BackupExport{},
				&commands.BackupPlan{},
				&commands.BackupImport{},
				&commands.BackupConfirm{},
				&commands.BackupRollback{},
				&commands.BackupStatus{},
			}
		}).
		WithRouting(func() {
			routes.Web()
			routes.Grpc()
		}).
		WithProviders(Providers).
		WithRunners(Runners).
		WithConfig(config.Boot).
		Create()
}
