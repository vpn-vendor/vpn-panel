package backupfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const (
	FormatName = "vpn-panel-settings"

	FormatVersion = 1

	MaxBytes = agentrpc.MaxMessageSize / 2
)

type Kind string

const (
	KindCopy Kind = "copy"

	KindTemplate Kind = "template"
)

type Document struct {
	Format        string             `json:"format"`
	FormatVersion int                `json:"format_version"`
	Kind          Kind               `json:"kind"`
	PanelVersion  string             `json:"panel_version"`
	CreatedAt     time.Time          `json:"created_at"`
	Sections      map[string]Section `json:"sections"`

	Secrets json.RawMessage `json:"secrets,omitempty"`
}

type Section struct {
	Version int             `json:"version"`
	Data    json.RawMessage `json:"data"`
}

var (
	ErrTooLarge        = errors.New("файл настроек больше допустимого размера")
	ErrMalformed       = errors.New("файл повреждён или это не файл настроек панели")
	ErrNewer           = errors.New("файл создан более новой версией панели — обновите панель и повторите")
	ErrUnknownSection  = errors.New("в файле раздел, которого эта версия панели не знает")
	ErrTemplateSecrets = errors.New("в шаблоне не может быть ключей и паролей — файл отвергнут")
)

func Parse(raw []byte) (*Document, error) {
	if len(raw) > MaxBytes {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: после документа лишние данные", ErrMalformed)
	}
	switch {
	case doc.Format != FormatName:
		return nil, ErrMalformed
	case doc.FormatVersion > FormatVersion:
		return nil, ErrNewer
	case doc.FormatVersion < 1:
		return nil, ErrMalformed
	case doc.Kind != KindCopy && doc.Kind != KindTemplate:
		return nil, fmt.Errorf("%w: неизвестный вид файла", ErrMalformed)
	case doc.Kind == KindTemplate && len(doc.Secrets) > 0:
		return nil, ErrTemplateSecrets
	case doc.Sections == nil:
		return nil, fmt.Errorf("%w: нет разделов", ErrMalformed)
	}
	for name, s := range doc.Sections {
		if name == "" || s.Version < 1 || len(s.Data) == 0 {
			return nil, fmt.Errorf("%w: раздел %q без версии или данных", ErrMalformed, name)
		}
	}
	return &doc, nil
}

func Marshal(doc *Document) ([]byte, error) {
	if doc.Kind == KindTemplate && len(doc.Secrets) > 0 {
		return nil, ErrTemplateSecrets
	}
	return json.MarshalIndent(doc, "", "  ")
}

type Spec struct {
	Version int
	Up      map[int]func(json.RawMessage) (json.RawMessage, error)
}

type Specs map[string]Spec

func (specs Specs) Validate() []error {
	var errs []error
	for name, sp := range specs {
		if sp.Version < 1 {
			errs = append(errs, fmt.Errorf("раздел %q: версия меньше 1", name))
			continue
		}
		for v := 1; v < sp.Version; v++ {
			if sp.Up[v] == nil {
				errs = append(errs, fmt.Errorf("раздел %q: нет шага миграции %d→%d", name, v, v+1))
			}
		}
		for v := range sp.Up {
			if v < 1 || v >= sp.Version {
				errs = append(errs, fmt.Errorf("раздел %q: лишний шаг миграции %d→%d", name, v, v+1))
			}
		}
	}
	return errs
}

func (specs Specs) Migrate(doc *Document) error {
	for name, s := range doc.Sections {
		sp, ok := specs[name]
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownSection, name)
		}
		if s.Version > sp.Version {
			return fmt.Errorf("%w (раздел %q)", ErrNewer, name)
		}
		for v := s.Version; v < sp.Version; v++ {
			up := sp.Up[v]
			if up == nil {
				return fmt.Errorf("раздел %q: нет шага миграции %d→%d", name, v, v+1)
			}
			data, err := up(s.Data)
			if err != nil {
				return fmt.Errorf("раздел %q, миграция %d→%d: %w", name, v, v+1, err)
			}
			s.Data = data
		}
		s.Version = sp.Version
		doc.Sections[name] = s
	}
	return nil
}
