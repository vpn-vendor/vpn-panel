package restore

import (
	"errors"
	"log"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

type Refusal struct {
	Text string
	Err  error
}

func (r *Refusal) Error() string { return r.Text }
func (r *Refusal) Unwrap() error { return r.Err }

func refuse(text string, cause error) error { return &Refusal{Text: text, Err: cause} }

const generic = "не удалось — подробности в системном журнале шлюза"

var known = []error{ErrPending, ErrDanger, ErrBusy, backup.ErrDangerousInTemplate,
	backupfile.ErrTooLarge, backupfile.ErrMalformed, backupfile.ErrNewer,
	backupfile.ErrUnknownSection, backupfile.ErrTemplateSecrets}

func Text(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		if r.Err == nil {
			return r.Text
		}
		return r.Text + ": " + Text(r.Err)
	}
	for _, k := range known {
		if errors.Is(err, k) {
			return k.Error()
		}
	}
	var terr *agentrpc.TransportError
	var aerr *agentrpc.ErrorObject
	if errors.As(err, &terr) || errors.As(err, &aerr) {
		return agentrpc.Human(err)
	}
	log.Printf("vpn-panel: импорт настроек: %v", err)
	return generic
}
