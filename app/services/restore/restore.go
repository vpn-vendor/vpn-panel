package restore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

const (
	SettingUntil  = "network.import_until"
	SettingWindow = "network.import_window"
)

var ErrPending = errors.New("предыдущий импорт не подтверждён и не откачен — сначала подтвердите или откатите его")

var ErrNoRoles = errors.New("роли карт не назначены")

var ErrBusy = errors.New("сеть шлюза только что применялась несколько раз подряд — подождите минуту и повторите")

const noRolesNote = " Роли сетевых карт не назначены — сеть шлюза оставлена как есть; назначьте роли на странице «Сеть»."

var ErrDanger = errors.New("в плане опасные изменения — примите их явно или откажитесь от импорта")

type Agent interface {
	Call(method string, params, out any) error
}

type System interface {
	ApplyNetwork(ip string) (awaiting bool, err error)
	ConfirmNetwork(ip string) error
	CancelNetwork(ip string)
	ApplyServices(ip string) string
	ApplyTunnel() error

	ConfirmTimeout() int

	Audit(event, ip, details string)

	Cards() ([]CardFacts, error)
}

type Store interface {
	Get(key string) string
	Set(key, value string) error
}

type Importer struct {
	Entries []backup.Entry
	Agent   Agent
	System  System
	Store   Store
	Version func() string
	Now     func() time.Time

	Sleep func(time.Duration)

	Lock func() (unlock func(), err error)

	Durable func() error
}

func (im *Importer) durable() error {
	if im.Durable == nil {
		return nil
	}
	return im.Durable()
}

func (im *Importer) applyNetwork(ip string) (bool, error) {
	budget := time.Duration(im.System.ConfirmTimeout()) * time.Second
	sleep := im.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var waited time.Duration
	for delay := time.Second; ; delay *= 2 {
		awaiting, err := im.System.ApplyNetwork(ip)
		if !errors.Is(err, ErrBusy) {
			return awaiting, err
		}

		pause := delay
		var busy *busyError
		if errors.As(err, &busy) {
			pause = max(delay, busy.wait)
		}
		if waited+pause > budget {
			return awaiting, err
		}
		sleep(pause)
		waited += pause
	}
}

type busyError struct {
	wait  time.Duration
	cause error
}

func (e *busyError) Error() string        { return ErrBusy.Error() + ": " + e.cause.Error() }
func (e *busyError) Is(target error) bool { return target == ErrBusy }
func (e *busyError) Unwrap() error        { return e.cause }

func (im *Importer) lock() (func(), error) {
	if im.Lock == nil {
		return func() {}, nil
	}
	return im.Lock()
}

type State struct {
	Pending bool
	Expired bool
	Until   time.Time

	Window bool
}

func (im *Importer) Current() State {

	if im.Store.Get(SettingUntil) == "" {
		return State{}
	}
	pending, expired, err := im.Pending()
	if err != nil || !pending {
		return State{}
	}
	until, _ := strconv.ParseInt(im.Store.Get(SettingUntil), 10, 64)
	return State{Pending: true, Expired: expired, Until: time.Unix(until, 0), Window: im.Store.Get(SettingWindow) == "1"}
}

type Secrets struct {
	File     []byte
	Password string
	Restore  json.RawMessage
}

type checkpointState struct {
	Exists bool `json:"exists"`
	Broken bool `json:"broken"`
}

func (im *Importer) checkpoint() (checkpointState, error) {
	var st checkpointState
	err := im.Agent.Call("backup.checkpoint_status", map[string]any{}, &st)
	return st, err
}

func (im *Importer) dropBroken(ip string) (string, error) {
	if err := im.Agent.Call("backup.checkpoint_drop", map[string]any{}, nil); err != nil {
		return "", err
	}
	im.clear()
	im.System.Audit("settings_import_broken", ip, "точка возврата повреждена обрывом питания до начала изменений и снята")
	return "Импорт прервался до начала изменений (обрыв питания) — настройки прежние, откатывать нечего.", nil
}

func (im *Importer) Pending() (pending, expired bool, err error) {
	st, err := im.checkpoint()
	if err != nil {
		return false, false, err
	}

	until, _ := strconv.ParseInt(im.Store.Get(SettingUntil), 10, 64)
	return st.Exists, st.Exists && im.Now().Unix() >= until, nil
}

func (im *Importer) OpenCopy(file []byte, password string) (*backupfile.Document, json.RawMessage, error) {
	var r struct {
		Document json.RawMessage `json:"document"`
		Secrets  json.RawMessage `json:"secrets"`
	}
	if err := im.Agent.Call("backup.open", map[string]any{"password": password, "file": base64.StdEncoding.EncodeToString(file)}, &r); err != nil {
		return nil, nil, err
	}
	doc, err := backupfile.Parse(r.Document)
	if err != nil {
		return nil, nil, err
	}
	return doc, r.Secrets, nil
}

func OpenTemplate(file []byte) (*backupfile.Document, error) {
	doc, err := backupfile.Parse(file)
	if err != nil {
		return nil, err
	}
	if doc.Kind != backupfile.KindTemplate {
		return nil, refuse("это копия, а не шаблон — откройте её с паролем копии", nil)
	}
	return doc, nil
}

func (im *Importer) Plan(doc *backupfile.Document) (*backup.Plan, error) {
	return backup.Prepare(im.Entries, doc)
}

func (im *Importer) Apply(ip string, plan *backup.Plan, sec *Secrets, acceptDanger bool) (awaitingNetwork bool, err error) {
	unlock, err := im.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if !plan.Ready() {
		return false, refuse("план не прошёл проверку: "+strings.Join(plan.Errors, "; "), nil)
	}
	if len(plan.Dangerous()) > 0 && !acceptDanger {
		return false, ErrDanger
	}
	if pending, _, err := im.Pending(); err != nil || pending {
		if err == nil {
			err = ErrPending
		}
		return false, err
	}
	cur, err := backup.Build(im.Entries, backupfile.KindCopy, im.Version(), im.Now())
	if err != nil {
		return false, err
	}
	raw, err := backupfile.Marshal(cur)
	if err != nil {
		return false, err
	}

	until := im.Now().Add(time.Duration(im.System.ConfirmTimeout()) * time.Second).Unix()
	if err := im.Store.Set(SettingUntil, strconv.FormatInt(until, 10)); err != nil {
		return false, err
	}
	if err := im.durable(); err != nil {
		return false, err
	}
	if err := im.Agent.Call("backup.checkpoint", map[string]any{"document": json.RawMessage(raw)}, nil); err != nil {
		im.clear()
		return false, err
	}
	if sec != nil {
		p := map[string]any{"password": sec.Password, "file": base64.StdEncoding.EncodeToString(sec.File), "restore": sec.Restore}
		if err := im.Agent.Call("backup.apply_secrets", p, nil); err != nil {
			return false, im.failed(ip, err)
		}
	}
	if err := plan.Write(ip); err != nil {
		return false, im.failed(ip, err)
	}
	if err := im.durable(); err != nil {
		return false, im.failed(ip, err)
	}
	awaiting, err := im.applyNetwork(ip)
	switch {
	case errors.Is(err, ErrNoRoles):
		im.System.ApplyServices(ip)
	case err != nil:
		return false, im.failed(ip, err)
	}
	if awaiting {
		if err := im.Store.Set(SettingWindow, "1"); err != nil {
			return true, err
		}
	}

	until = im.Now().Add(time.Duration(im.System.ConfirmTimeout()) * time.Second).Unix()
	if err := im.Store.Set(SettingUntil, strconv.FormatInt(until, 10)); err != nil {
		return awaiting, err
	}
	im.System.Audit("settings_import", ip, "настройки из файла применены, ждут подтверждения")
	return awaiting, nil
}

func (im *Importer) ConfirmNetwork(ip string) error {
	unlock, err := im.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if im.Store.Get(SettingWindow) != "1" {
		return nil
	}
	if err := im.System.ConfirmNetwork(ip); err != nil {
		return im.failed(ip, err)
	}
	return im.Store.Set(SettingWindow, "")
}

func (im *Importer) failed(ip string, cause error) error {
	if _, err := im.rollback(ip, "импорт не удался", eventRolledBack); err != nil {
		return refuse("импорт не удался ("+Text(cause)+"), и откат тоже — повторите откат", err)
	}
	return refuse("импорт не удался и откачен", cause)
}

func (im *Importer) Confirm(ip string) (string, error) {
	unlock, err := im.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if st, err := im.checkpoint(); err == nil && st.Broken {
		return im.dropBroken(ip)
	}
	pending, expired, err := im.Pending()
	switch {
	case err != nil:
		return "", err
	case !pending:
		return "", refuse("подтверждать нечего: незавершённого импорта нет", nil)
	case expired:
		if _, err := im.rollback(ip, "срок подтверждения истёк", eventRolledBack); err != nil {
			return "", refuse("срок подтверждения истёк, откат не удался", err)
		}
		return "", refuse("срок подтверждения истёк — импорт откачен", nil)
	}
	if im.Store.Get(SettingWindow) == "1" {
		if err := im.System.ConfirmNetwork(ip); err != nil {
			return "", im.failed(ip, err)
		}
	}
	if err := im.System.ApplyTunnel(); err != nil {
		return "", im.failed(ip, err)
	}

	if err := im.durable(); err != nil {
		return "", err
	}
	if err := im.Agent.Call("backup.checkpoint_drop", map[string]any{}, nil); err != nil {
		return "", err
	}
	im.clear()
	im.System.Audit("settings_import_confirmed", ip, "настройки из файла закреплены")
	return "Настройки из файла применены и закреплены.", nil
}

func (im *Importer) Rollback(ip string) (string, error) {
	unlock, err := im.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if st, err := im.checkpoint(); err == nil && st.Broken {
		return im.dropBroken(ip)
	}
	return im.rollback(ip, "откат по решению администратора", eventRolledBack)
}

func (im *Importer) Expire() (bool, error) {
	unlock, err := im.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if st, err := im.checkpoint(); err == nil && st.Broken {
		_, err = im.dropBroken("")
		return true, err
	}
	pending, expired, err := im.Pending()
	if err != nil || !pending || !expired {
		return false, err
	}
	_, err = im.rollback("", "срок подтверждения истёк", eventExpired)
	return true, err
}

const (
	eventRolledBack = "settings_import_rolled_back"
	eventExpired    = "settings_import_expired"
)

func (im *Importer) rollback(ip, why, event string) (string, error) {
	note := ""
	var r struct {
		Document json.RawMessage `json:"document"`
	}
	if err := im.Agent.Call("backup.checkpoint_document", map[string]any{}, &r); err != nil {
		return "", err
	}
	doc, err := backupfile.Parse(r.Document)
	if err != nil {
		return "", err
	}
	plan, err := backup.Prepare(im.Entries, doc)
	if err != nil {
		return "", err
	}
	if err := im.Agent.Call("backup.checkpoint_secrets", map[string]any{"prune": false}, nil); err != nil {
		return "", err
	}
	if err := plan.Write(ip); err != nil {
		return "", err
	}
	if err := im.durable(); err != nil {
		return "", err
	}
	until, _ := strconv.ParseInt(im.Store.Get(SettingUntil), 10, 64)
	if im.Store.Get(SettingWindow) == "1" && im.Now().Unix() < until {

		im.System.CancelNetwork(ip)
		im.System.ApplyServices(ip)
	} else {
		awaiting, err := im.applyNetwork(ip)
		switch {
		case errors.Is(err, ErrNoRoles):

			note = noRolesNote
			im.System.ApplyServices(ip)
		case err != nil:
			return "", err
		}

		if awaiting {
			if err := im.System.ConfirmNetwork(ip); err != nil {
				return "", err
			}
		}
	}
	if err := im.System.ApplyTunnel(); err != nil {
		return "", err
	}
	if err := im.Agent.Call("backup.checkpoint_secrets", map[string]any{"prune": true}, nil); err != nil {
		return "", err
	}
	if err := im.durable(); err != nil {
		return "", err
	}
	if err := im.Agent.Call("backup.checkpoint_drop", map[string]any{}, nil); err != nil {
		return "", err
	}
	im.clear()
	im.System.Audit(event, ip, why)
	return "Импорт откачен: настройки возвращены к состоянию до импорта." + note, nil
}

func (im *Importer) clear() {
	_ = im.Store.Set(SettingUntil, "")
	_ = im.Store.Set(SettingWindow, "")
	_ = im.durable()
}
