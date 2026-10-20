package commands

import (
	"fmt"
	"strings"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type DBCheck struct{}

func (c *DBCheck) Signature() string { return "db:check" }
func (c *DBCheck) Description() string {
	return "Проверить целостность базы настроек (код выхода 0 — цела)"
}
func (c *DBCheck) Extend() command.Extend { return command.Extend{} }

func (c *DBCheck) Handle(console.Context) error {
	var rows []struct {
		IntegrityCheck string `gorm:"column:integrity_check"`
	}
	if err := facades.Orm().Query().Raw("PRAGMA integrity_check").Scan(&rows); err != nil {
		return fmt.Errorf("база не открывается: %w", err)
	}
	var bad []string
	for _, r := range rows {
		if r.IntegrityCheck != "ok" {
			bad = append(bad, r.IntegrityCheck)
		}
	}
	if len(rows) == 0 || len(bad) > 0 {
		return fmt.Errorf("база повреждена: %s", strings.Join(bad, "; "))
	}
	fmt.Println("база цела")
	return nil
}
