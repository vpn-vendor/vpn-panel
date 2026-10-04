package restore

import (
	"encoding/base64"
	"encoding/json"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

func (im *Importer) ExportTemplate() ([]byte, error) {
	doc, err := backup.Build(im.Entries, backupfile.KindTemplate, im.Version(), im.Now())
	if err != nil {
		return nil, err
	}
	return backupfile.Marshal(doc)
}

func (im *Importer) ExportCopy(code, password string) ([]byte, error) {
	doc, err := backup.Build(im.Entries, backupfile.KindCopy, im.Version(), im.Now())
	if err != nil {
		return nil, err
	}
	plain, err := backupfile.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var r struct {
		File string `json:"file"`
	}
	if err := im.Agent.Call("backup.export", map[string]any{"code": code, "password": password, "document": json.RawMessage(plain)}, &r); err != nil {
		return nil, err
	}
	if r.File == "" {
		return nil, refuse("служба не вернула файл копии — повторите", nil)
	}
	return base64.StdEncoding.DecodeString(r.File)
}
