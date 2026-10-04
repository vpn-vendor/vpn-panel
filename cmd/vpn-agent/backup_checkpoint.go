package main

import (
	"encoding/json"
	"errors"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

var checkpointFile = "/etc/vpn-panel/import-checkpoint.json"

const codeBackupPending = 2109

type checkpoint struct {
	CreatedAt time.Time       `json:"created_at"`
	Document  json.RawMessage `json:"document"`
	Secrets   backupSecrets   `json:"secrets"`
}

func readCheckpoint() (*checkpoint, error) {
	data, err := os.ReadFile(checkpointFile)
	if err != nil {
		return nil, err
	}
	var c checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (b *backupApplier) backupCheckpoint(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	doc, err := backupfile.Parse(p.Document)
	if err != nil || doc.Kind != backupfile.KindCopy {
		return nil, backupErr(codeBackupFile, "текущие настройки не собрались в копию — повторите")
	}
	if _, err := os.Stat(checkpointFile); err == nil {
		return nil, backupErr(codeBackupPending, "предыдущий импорт не подтверждён и не откачен — сначала завершите его")
	}
	sec, err := b.collect()
	if err != nil {
		return nil, detailErr("не удалось собрать ключи для точки возврата — повторите", err.Error(), true)
	}
	c := checkpoint{CreatedAt: time.Now().UTC(), Document: p.Document, Secrets: sec}
	data, err := json.Marshal(c)
	if err == nil {
		err = durable.Write(checkpointFile, data, 0o600)
	}
	if err != nil {
		return nil, detailErr("точка возврата не записана — импорт не начат", err.Error(), true)
	}
	log.Printf("backup: точка возврата импорта снята (профилей: %d)", len(sec.Profiles))
	return map[string]any{"created_at": c.CreatedAt}, nil
}

func (b *backupApplier) backupCheckpointStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	c, err := readCheckpoint()
	switch {
	case errors.Is(err, os.ErrNotExist):
		return map[string]any{"exists": false}, nil
	case err != nil:

		log.Printf("backup: точка возврата повреждена: %v", err)
		return map[string]any{"exists": true, "broken": true}, nil
	}
	return map[string]any{"exists": true, "created_at": c.CreatedAt}, nil
}

func (b *backupApplier) backupCheckpointDocument(json.RawMessage) (any, *agentrpc.ErrorObject) {
	c, err := readCheckpoint()
	if err != nil {
		return nil, backupErr(codeBackupFile, "точки возврата нет — откатывать нечего")
	}
	return map[string]any{"document": c.Document}, nil
}

func (b *backupApplier) backupCheckpointSecrets(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		Prune bool `json:"prune"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	c, err := readCheckpoint()
	if err != nil {
		return nil, backupErr(codeBackupFile, "точки возврата нет — откатывать нечего")
	}
	if p.Prune {
		return b.prune(c.Secrets)
	}
	choice := restoreChoice{PPPoE: c.Secrets.PPPoE != nil}
	for _, s := range c.Secrets.Profiles {
		choice.Profiles = append(choice.Profiles, profileRef{Protocol: s.Protocol, Slug: s.Slug})
	}
	return b.restore(c.Secrets, choice)
}

func (b *backupApplier) backupCheckpointDrop(json.RawMessage) (any, *agentrpc.ErrorObject) {

	if err := durable.Remove(checkpointFile); err != nil {
		return nil, detailErr("точка возврата не удалена — повторите", err.Error(), true)
	}
	log.Printf("backup: импорт подтверждён, точка возврата удалена")
	return map[string]any{"dropped": true}, nil
}

func (v *vpnApplier) pruneSecrets(keep backupSecrets) (map[string]any, *agentrpc.ErrorObject) {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.readState()
	removed, kept := []string{}, []string{}
	for proto, drv := range v.drivers {
		for _, slug := range drv.listProfiles() {
			if _, ok := keep.find(profileRef{Protocol: proto, Slug: slug}); ok {
				continue
			}
			if st.Plan.Mode == modeBlack && st.Plan.Slug == slug {
				kept = append(kept, slug)
				continue
			}
			if err := drv.removeProfile(slug, false); err != nil {
				return nil, detailErr("профиль "+slug+" не убран — повторите откат", err.Error(), true)
			}
			removed = append(removed, slug)
		}
	}
	log.Printf("backup: откат — убрано профилей %d, оставлен активный: %v", len(removed), kept)
	return map[string]any{"removed": removed, "kept_active": kept}, nil
}
