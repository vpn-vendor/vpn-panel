package config

import (
	"fmt"

	"github.com/goravel/framework/contracts/database/driver"
	sqlitefacades "github.com/goravel/sqlite/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

func sqliteDSN(path any) string {
	file := "storage/app/panel.sqlite"
	if s, ok := path.(string); ok && s != "" {
		file = s
	}
	return fmt.Sprintf(

		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=journal_size_limit(67108864)",
		file,
	)
}

func init() {
	config := facades.Config()
	config.Add("database", map[string]any{

		"default": config.Env("DB_CONNECTION", "sqlite"),

		"connections": map[string]any{
			"sqlite": map[string]any{
				"database": config.Env("DB_DATABASE", "storage/app/panel.sqlite"),
				"prefix":   "",
				"singular": false,
				"dsn":      sqliteDSN(config.Env("DB_DATABASE", "storage/app/panel.sqlite")),
				"via": func() (driver.Driver, error) {
					return sqlitefacades.Sqlite("sqlite")
				},
			},
		},

		"pool": map[string]any{

			"max_idle_conns": 4,

			"max_open_conns": 8,

			"conn_max_idletime": 3600,

			"conn_max_lifetime": 3600,
		},

		"slow_threshold": 200,

		"migrations": map[string]any{
			"table": "migrations",
		},
	})
}
