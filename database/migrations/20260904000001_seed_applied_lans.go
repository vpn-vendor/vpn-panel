package migrations

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

type M20260904000001SeedAppliedLans struct{}

func (r *M20260904000001SeedAppliedLans) Signature() string {
	return "20260904000001_seed_applied_lans"
}

const appliedLansKey = "network.applied_lans"

func (r *M20260904000001SeedAppliedLans) Up() error {
	var existing models.Setting
	if err := facades.Orm().Query().Where("key", appliedLansKey).First(&existing); err == nil && existing.Key != "" {
		return nil
	}
	var rows []models.Interface
	if err := facades.Orm().Query().Where("role", "lan").Find(&rows); err != nil {
		return err
	}
	var cidrs []string
	for _, row := range rows {
		if row.IPv4CIDR != "" {
			cidrs = append(cidrs, row.IPv4CIDR)
		}
	}
	if len(cidrs) == 0 {
		return nil
	}
	sort.Strings(cidrs)
	raw, err := json.Marshal(cidrs)
	if err != nil {
		return err
	}
	return facades.Orm().Query().Create(&models.Setting{
		Key: appliedLansKey, Value: string(raw), UpdatedAt: time.Now(),
	})
}

func (r *M20260904000001SeedAppliedLans) Down() error {
	_, err := facades.Orm().Query().Where("key", appliedLansKey).Delete(&models.Setting{})
	return err
}
