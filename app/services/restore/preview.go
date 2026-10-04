package restore

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
)

type CardFacts struct {
	backup.Card
	Link      bool
	Addresses []string
	Provider  bool
	SpeedMbit int
}

type Preview struct {
	Plan *backup.Plan

	Ask    []backup.Ref
	Choice map[string]string
	Cards  []CardFacts

	Hints []string
}

func (im *Importer) Preview(doc *backupfile.Document, choice map[string]string) (*Preview, error) {
	refs, err := backup.Refs(im.Entries, doc)
	if err != nil {
		return nil, err
	}
	pv := &Preview{Choice: choice}
	var errs []string
	if len(refs) > 0 {
		if pv.Cards, err = im.System.Cards(); err != nil {
			return nil, err
		}
		here := make([]backup.Card, 0, len(pv.Cards))
		for _, c := range pv.Cards {
			here = append(here, c.Card)
		}
		_, pv.Ask = backup.Match(refs, here)
		to, aerrs := backup.Assign(refs, here, choice)
		errs = aerrs
		if len(errs) == 0 {
			if err := backup.Remap(im.Entries, doc, to); err != nil {
				return nil, err
			}
			pv.Hints = cableHints(refs, to, pv.Cards)
		}
	}
	if pv.Plan, err = backup.Prepare(im.Entries, doc); err != nil {
		return nil, err
	}
	pv.Plan.Errors = append(errs, pv.Plan.Errors...)
	return pv, nil
}

func cableHints(refs []backup.Ref, to map[string]backup.Card, cards []CardFacts) []string {
	facts := map[string]CardFacts{}
	var answered []string
	for _, c := range cards {
		facts[c.Name] = c
		if c.Provider {
			answered = append(answered, c.Name)
		}
	}
	var out []string
	for _, r := range refs {
		if r.Field("role") != netplangen.RoleWAN {
			continue
		}
		wan := to[r.Card.Name].Name
		f := facts[wan]
		switch {
		case len(answered) > 0 && !f.Provider:
			out = append(out, fmt.Sprintf("Сейчас интернет приходит в карту %s, а по файлу его получит карта %s. Переставьте кабель провайдера в карту %s или назначьте ей другую роль.", answered[0], wan, wan))
		case !f.Link:
			out = append(out, fmt.Sprintf("В карте %s нет кабеля, а по файлу она смотрит в интернет. Кабель провайдера должен быть в карте %s.", wan, wan))
		}
	}
	return out
}
