package qos

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
)

type Section struct {
	Enabled  bool `json:"enabled" setting:"qos.enabled"`
	DownKbit int  `json:"down_kbit" setting:"qos.down_kbit"`
	UpKbit   int  `json:"up_kbit" setting:"qos.up_kbit"`
}

func ReadSection() (Section, error) {
	return Section{
		Enabled:  settings.Get(SettingEnabled) == "1",
		DownKbit: atoiSafe(settings.Get(SettingDownKbit)),
		UpKbit:   atoiSafe(settings.Get(SettingUpKbit)),
	}, nil
}

func ValidateSection(v Section) fielderr.List {
	var errs fielderr.List
	for _, f := range []struct {
		path string
		kbit int
	}{{"down_kbit", v.DownKbit}, {"up_kbit", v.UpKbit}} {
		switch {
		case f.kbit == 0 && v.Enabled:
			errs.Add(f.path, "включённой очереди нужна скорость тарифа")
		case f.kbit != 0 && (f.kbit < qosgen.MinKbit || f.kbit > qosgen.MaxKbit):
			errs.Add(f.path, "скорость — от %d до %d кбит/с", qosgen.MinKbit, qosgen.MaxKbit)
		}
	}
	return errs
}

func ApplySection(cur, want Section) error { return settings.WriteChanged(cur, want) }

func Edit(edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection, Validate: ValidateSection, Apply: ApplySection}, edit)
}
