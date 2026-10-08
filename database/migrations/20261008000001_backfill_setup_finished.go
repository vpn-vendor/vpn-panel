package migrations

import (
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

type M20261008000001BackfillSetupFinished struct{}

func (r *M20261008000001BackfillSetupFinished) Signature() string {
	return "20261008000001_backfill_setup_finished"
}

func (r *M20261008000001BackfillSetupFinished) Up() error {
	q := facades.Orm().Query()
	var finished models.Setting
	if err := q.Where("key", "setup.finished").First(&finished); err == nil && finished.Key != "" {
		return nil
	}
	var lans models.Setting
	if err := q.Where("key", "network.applied_lans").First(&lans); err != nil {
		return nil
	}
	if lans.Value == "" || lans.Value == "[]" || lans.Value == "null" {
		return nil
	}
	return q.Create(&models.Setting{Key: "setup.finished", Value: "1", UpdatedAt: time.Now()})
}

func (r *M20261008000001BackfillSetupFinished) Down() error {

	return nil
}
