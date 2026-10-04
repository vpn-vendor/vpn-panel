package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

const dangerWord = "RISK"

const slotLife = 15 * time.Minute

var ageHeader = []byte("age-encryption.org/v1")

type importFile struct {
	device   uint
	name     string
	doc      []byte
	secrets  json.RawMessage
	file     []byte
	password string
	choice   map[string]string
	at       time.Time
}

type importSlot struct {
	mu sync.Mutex
	f  *importFile
}

var slot importSlot

func (s *importSlot) take(device uint, now time.Time) (importFile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil || s.f.device != device || now.Sub(s.f.at) > slotLife {
		return importFile{}, false
	}
	return *s.f, true
}

func (s *importSlot) put(v importFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.f = &v
}

func (s *importSlot) setChoice(device uint, choice map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil && s.f.device == device {
		s.f.choice = choice
	}
}

func (s *importSlot) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.f = nil
}

type BackupController struct {
	im func() *restore.Importer
}

func NewBackupController() *BackupController {
	return &BackupController{im: restore.Live}
}

func deviceOf(ctx contractshttp.Context) uint {
	if d, ok := ctx.Value(middleware.CtxDevice).(*models.TrustedDevice); ok && d != nil {
		return d.ID
	}
	return 0
}

func (c *BackupController) back(ctx contractshttp.Context, to, errText string) contractshttp.Response {
	if errText != "" {
		setFlash(ctx, flashError, errText)
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, to)
}

func errText(err error) string { return restore.Text(err) }

func (c *BackupController) Index(ctx contractshttp.Context) contractshttp.Response {
	st := c.im().Current()
	view := map[string]any{
		"error":   takeFlash(ctx, flashError),
		"ok":      takeFlash(ctx, flashCode),
		"pending": st.Pending,
		"expired": st.Expired,
		"until":   st.Until.Local().Format("15:04:05"),
		"codeField": ui.Field{ID: "code", Name: "code", Label: "Код с экрана шлюза", Autocomplete: "off", MaxLength: 16,
			Hint: "Значок «Код для копии настроек» на рабочем столе шлюза или команда sudo vpn-panel-backup-code", Required: true},
		"passField": ui.Field{ID: "password", Name: "password", Label: "Пароль копии", Type: "password", Autocomplete: "new-password", Required: true,
			Hint: "Те же правила, что у пароля диска. Без пароля копию не открыть никому, в том числе нам"},
		"pass2Field": ui.Field{ID: "password2", Name: "password2", Label: "Пароль ещё раз", Type: "password", Autocomplete: "new-password", Required: true},
		"fileField": ui.FileField{ID: "file", Name: "file", Label: "Файл копии или шаблона", Accept: ".vpnpanel,.json", Required: true,
			Hint: "Своя копия восстанавливает всё, шаблон — только правила офиса"},
		"openField":  ui.Field{ID: "open-password", Name: "password", Label: "Пароль копии", Type: "password", Autocomplete: "off", Hint: "Для шаблона не нужен"},
		"exportBtn":  ui.Button{Label: "Выгрузить копию"},
		"tmplBtn":    ui.Button{Label: "Выгрузить шаблон", Kind: "secondary"},
		"uploadBtn":  ui.Button{Label: "Открыть файл"},
		"confirmBtn": ui.Button{Label: "Закрепить настройки"},
		"undoBtn":    ui.Button{Label: "Откатить импорт", Kind: "danger"},
	}
	if _, ok := slot.take(deviceOf(ctx), time.Now()); ok {
		view["hasSlot"] = true
	}
	return ctx.Response().View().Make("backup.tmpl", page(ctx, "Резервная копия", "backup", view))
}

func attachment(ctx contractshttp.Context, name, kind string, data []byte) contractshttp.Response {
	ctx.Response().Header("Content-Disposition", `attachment; filename="`+name+`"`)
	ctx.Response().Header("Cache-Control", "no-store")
	return ctx.Response().Data(contractshttp.StatusOK, kind, data)
}

func (c *BackupController) ExportTemplate(ctx contractshttp.Context) contractshttp.Response {
	im := c.im()
	data, err := im.ExportTemplate()
	if err != nil {
		return c.back(ctx, "/backup", "Шаблон не собрался: "+errText(err))
	}
	im.System.Audit("settings_export", ctx.Request().Ip(), "выгружен шаблон настроек")
	return attachment(ctx, "vpn-panel-"+time.Now().Format("2006-01-02")+".vpnpanel.json", "application/json", data)
}

func (c *BackupController) ExportCopy(ctx contractshttp.Context) contractshttp.Response {
	code := strings.ToUpper(strings.TrimSpace(ctx.Request().Input("code")))
	pass := ctx.Request().Input("password")
	if pass != ctx.Request().Input("password2") {
		return c.back(ctx, "/backup", "Пароли не совпали — введите пароль копии дважды одинаково.")
	}
	im := c.im()
	data, err := im.ExportCopy(code, pass)
	if err != nil {
		return c.back(ctx, "/backup", "Копия не выгружена: "+errText(err))
	}
	im.System.Audit("settings_export", ctx.Request().Ip(), "выгружена полная копия настроек")
	im.MarkExported(ctx.Request().Ip())
	return attachment(ctx, "vpn-panel-"+time.Now().Format("2006-01-02")+".vpnpanel", "application/octet-stream", data)
}

func (c *BackupController) Upload(ctx contractshttp.Context) contractshttp.Response {
	file, err := ctx.Request().File("file")
	if err != nil {
		return c.back(ctx, "/backup", "Файл не выбран — нажмите «Выберите файл» и укажите копию или шаблон.")
	}
	path := file.File()
	defer func() { _ = os.Remove(path) }()
	if size, serr := file.Size(); serr == nil && size > backupfile.MaxBytes {
		return c.back(ctx, "/backup", "Файл слишком большой для копии настроек — проверьте, что выбран нужный файл.")
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return c.back(ctx, "/backup", "Не удалось прочитать файл — попробуйте ещё раз.")
	}
	im := c.im()
	v := importFile{device: deviceOf(ctx), name: file.GetClientOriginalName(), at: time.Now()}
	var doc *backupfile.Document
	if bytes.HasPrefix(data, ageHeader) {
		pass := ctx.Request().Input("password")
		if pass == "" {
			return c.back(ctx, "/backup", "Это зашифрованная копия — введите её пароль.")
		}
		if doc, v.secrets, err = im.OpenCopy(data, pass); err != nil {
			return c.back(ctx, "/backup", "Копия не открылась: "+errText(err))
		}
		v.file, v.password = data, pass
	} else if doc, err = restore.OpenTemplate(data); err != nil {
		return c.back(ctx, "/backup", "Файл не открылся: "+errText(err))
	}
	if v.doc, err = backupfile.Marshal(doc); err != nil {
		return c.back(ctx, "/backup", "Файл не открылся: "+errText(err))
	}
	slot.put(v)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup/import")
}

func (c *BackupController) preview(v importFile) (*restore.Importer, *restore.Preview, error) {
	doc, err := backupfile.Parse(v.doc)
	if err != nil {
		return nil, nil, err
	}
	im := c.im()
	pv, err := im.Preview(doc, v.choice)
	return im, pv, err
}

func (c *BackupController) Preview(ctx contractshttp.Context) contractshttp.Response {
	v, ok := slot.take(deviceOf(ctx), time.Now())
	if !ok {
		return c.back(ctx, "/backup", "Файл для импорта не выбран или ждал слишком долго — откройте его ещё раз.")
	}
	_, pv, err := c.preview(v)
	if err != nil {
		return c.back(ctx, "/backup", "Файл не подходит: "+errText(err))
	}
	view := map[string]any{
		"error":    takeFlash(ctx, flashError),
		"fileName": v.name,
		"isCopy":   v.file != nil,
		"hints":    pv.Hints,
		"errors":   pv.Plan.Errors,
		"ready":    pv.Plan.Ready(),
		"sections": sectionRows(pv.Plan),
		"cardBtn":  ui.Button{Label: "Назначить карты", Kind: "secondary"},
		"applyBtn": ui.Button{Label: "Применить настройки"},
		"dropBtn":  ui.Button{Label: "Отказаться", Kind: "ghost"},
	}
	if len(pv.Ask) > 0 {
		view["cards"] = cardQuestions(pv)
		view["cardFacts"] = cardFacts(pv.Cards)
	}
	if rows := dangerRows(pv.Plan); len(rows) > 0 {
		view["danger"] = ui.DangerConfirm{Word: dangerWord, Rows: rows,
			Submit: ui.Button{Label: "Принять риск и применить", Kind: "danger", Name: "accept_danger", Value: "1"}}
	}
	return ctx.Response().View().Make("backup_preview.tmpl", page(ctx, "Импорт настроек", "backup", view))
}

type sectionRow struct {
	Title  string
	State  string
	Items  []string
	Absent bool
}

var kindWords = map[string]string{backup.Changed: "изменится", backup.Added: "добавится", backup.Removed: "удалится"}

func sectionRows(p *backup.Plan) []sectionRow {
	var out []sectionRow
	for _, s := range p.Sections {
		r := sectionRow{Title: s.Name.Title()}
		switch {
		case !s.InFile:
			r.State, r.Absent = "нет в файле — останется как есть", true
		case len(s.Changes) == 0:
			r.State = "останется как есть"
		default:
			plain := 0
			for _, ch := range s.Changes {
				if ch.Item == "" || ch.Item == "строка" {
					plain++
					continue
				}
				r.Items = append(r.Items, "«"+ch.Item+"» — "+kindWords[ch.Kind])
			}
			r.State = "изменится"
			if plain > 0 {
				r.State = "изменится: " + ui.Plural(plain, "настройка", "настройки", "настроек")
			}
		}
		out = append(out, r)
	}
	return out
}

func dangerRows(p *backup.Plan) []ui.DangerRow {
	var out []ui.DangerRow
	for i, ch := range p.Dangerous() {
		item := ch.Item
		if item == "строка" {
			item = ""
		}
		out = append(out, ui.DangerRow{Name: fmt.Sprintf("danger_%d", i), Title: ch.Title, Item: item, Kind: kindWords[ch.Kind], Warn: ch.Warn})
	}
	return out
}

type cardQuestion struct {
	Role   string
	Select ui.Select
}

var roleWords = map[string]string{"wan": "смотрела в интернет", "lan": "смотрела в офис"}

func cardQuestions(pv *restore.Preview) []cardQuestion {
	var out []cardQuestion
	for i, r := range pv.Ask {
		opts := []ui.Option{{Value: "", Label: "— выберите карту —"}}
		for _, c := range pv.Cards {
			opts = append(opts, ui.Option{Value: c.Name, Label: c.Name + " (" + strings.Join(factWords(c), ", ") + ")"})
		}
		role := roleWords[r.Field("role")]
		if role == "" {
			role = "без роли"
		}
		out = append(out, cardQuestion{Role: role, Select: ui.Select{ID: fmt.Sprintf("card-%d", i), Name: "card_" + r.Card.Name,
			Label: "Карта «" + r.Card.Name + "» из файла", Value: pv.Choice[r.Card.Name], Options: opts}})
	}
	return out
}

func factWords(c restore.CardFacts) []string {
	w := []string{"кабеля нет"}
	if c.Link {
		w = []string{"кабель есть"}
	}
	if c.SpeedMbit > 0 {
		w = append(w, fmt.Sprintf("%d Мбит/с", c.SpeedMbit))
	}
	if c.Provider {
		w = append(w, "провайдер ответил")
	}
	return w
}

type cardFact struct {
	Name, MAC, Facts string
}

func cardFacts(cards []restore.CardFacts) []cardFact {
	out := make([]cardFact, 0, len(cards))
	for _, c := range cards {
		out = append(out, cardFact{Name: c.Name, MAC: c.MAC, Facts: strings.Join(factWords(c), ", ")})
	}
	return out
}

func (c *BackupController) Cards(ctx contractshttp.Context) contractshttp.Response {
	v, ok := slot.take(deviceOf(ctx), time.Now())
	if !ok {
		return c.back(ctx, "/backup", "Файл для импорта не выбран или ждал слишком долго — откройте его ещё раз.")
	}
	_, pv, err := c.preview(importFile{doc: v.doc})
	if err != nil {
		return c.back(ctx, "/backup", "Файл не подходит: "+errText(err))
	}
	choice := map[string]string{}
	for _, r := range pv.Ask {
		if want := strings.TrimSpace(ctx.Request().Input("card_" + r.Card.Name)); want != "" {
			choice[r.Card.Name] = want
		}
	}
	slot.setChoice(v.device, choice)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup/import")
}

func (c *BackupController) Apply(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	v, ok := slot.take(deviceOf(ctx), time.Now())
	if !ok {
		return c.back(ctx, "/backup", "Файл для импорта не выбран или ждал слишком долго — откройте его ещё раз.")
	}
	im, pv, err := c.preview(v)
	if err != nil {
		return c.back(ctx, "/backup", "Файл не подходит: "+errText(err))
	}
	if !pv.Plan.Ready() {
		return c.back(ctx, "/backup/import", "План не готов — исправьте то, что названо в списке, и повторите.")
	}
	danger := dangerRows(pv.Plan)
	accepted := len(danger) > 0
	for _, r := range danger {
		if ctx.Request().Input(r.Name) != "1" {
			accepted = false
		}
	}
	if len(danger) > 0 && (!accepted || !strings.EqualFold(strings.TrimSpace(ctx.Request().Input("danger_word")), dangerWord)) {
		return c.back(ctx, "/backup/import", "Отметьте каждую опасную строку и наберите слово "+dangerWord+" — иначе опасные изменения не применяются.")
	}
	var sec *restore.Secrets
	if v.file != nil {
		sec = &restore.Secrets{File: v.file, Password: v.password, Restore: v.secrets}
	}
	awaiting, err := im.Apply(ip, pv.Plan, sec, accepted)
	if err != nil {
		return c.back(ctx, "/backup", "Импорт не выполнен: "+errText(err))
	}
	slot.drop()
	if awaiting {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/backup/confirming")
	}
	setFlash(ctx, flashCode, "Настройки из файла применены. Проверьте, что всё работает, и нажмите «Закрепить настройки» — без этого они вернутся к прежним сами.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup")
}

func (c *BackupController) Discard(ctx contractshttp.Context) contractshttp.Response {
	slot.drop()
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup")
}

func (c *BackupController) Confirming(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().View().Make("network_confirming.tmpl",
		page(ctx, "Проверка связи", "backup", map[string]any{
			"timeout":    c.im().System.ConfirmTimeout(),
			"confirmURL": "/backup/confirm-network",
			"cancelURL":  "/backup/rollback",
			"returnURL":  "/backup",
		}))
}

func (c *BackupController) ConfirmNetwork(ctx contractshttp.Context) contractshttp.Response {
	if err := c.im().ConfirmNetwork(ctx.Request().Ip()); err != nil {
		return c.back(ctx, "/backup", "Связь не подтвердилась, импорт откачен: "+errText(err))
	}
	setFlash(ctx, flashCode, "Связь с панелью в порядке. Проверьте, что всё работает, и нажмите «Закрепить настройки» — без этого они вернутся к прежним сами.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup")
}

func (c *BackupController) Confirm(ctx contractshttp.Context) contractshttp.Response {
	msg, err := c.im().Confirm(ctx.Request().Ip())
	if err != nil {
		return c.back(ctx, "/backup", errText(err))
	}
	setFlash(ctx, flashCode, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup")
}

func (c *BackupController) Rollback(ctx contractshttp.Context) contractshttp.Response {
	msg, err := c.im().Rollback(ctx.Request().Ip())
	if err != nil {
		return c.back(ctx, "/backup", "Откат не удался: "+errText(err)+" Повторите откат.")
	}
	setFlash(ctx, flashCode, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/backup")
}
