package restore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type metrics struct {
	Master string `json:"master" setting:"metrics.master"`
}

type vpnMode struct {
	Mode string `json:"mode" setting:"vpn.mode"`
}

type world struct {
	cards        []CardFacts
	master, mode string
	failWrite    bool
	calls        []string
	checkpoint   json.RawMessage
	awaiting     bool
	confirmErr   error
	now          time.Time
	slow         time.Duration
	noRoles      bool
	busy         int
	broken       bool
	store        map[string]string
}

func (w *world) log(s string) { w.calls = append(w.calls, s) }

func (w *world) entries() []backup.Entry {
	return []backup.Entry{
		backup.Of(backup.Def[metrics]{Name: settings.SectionMetrics, Version: 1,
			Read:     func() (metrics, error) { return metrics{Master: w.master}, nil },
			Validate: func(metrics, backup.Desired) fielderr.List { return nil },
			Apply: func(_, want metrics, _ string) error {
				if w.failWrite {
					w.failWrite = false
					return errors.New("база недоступна")
				}
				w.log("запись metrics=" + want.Master)
				w.master = want.Master
				return nil
			}}),
		backup.Of(backup.Def[vpnMode]{Name: settings.SectionVPN, Version: 1,
			Read:     func() (vpnMode, error) { return vpnMode{Mode: w.mode}, nil },
			Validate: func(vpnMode, backup.Desired) fielderr.List { return nil },
			Apply: func(_, want vpnMode, _ string) error {
				w.log("запись vpn=" + want.Mode)
				w.mode = want.Mode
				return nil
			}}),
	}
}

func (w *world) Call(method string, params, out any) error {
	w.log(method)
	p, _ := json.Marshal(params)
	var in map[string]json.RawMessage
	_ = json.Unmarshal(p, &in)
	reply := map[string]any{}
	switch method {
	case "backup.checkpoint_status":
		reply["exists"] = w.checkpoint != nil || w.broken
		reply["broken"] = w.broken
	case "backup.checkpoint":
		w.checkpoint = in["document"]
	case "backup.checkpoint_document":
		reply["document"] = w.checkpoint
	case "backup.checkpoint_drop":
		w.checkpoint, w.broken = nil, false
	case "backup.export":

		reply["file"] = base64.StdEncoding.EncodeToString(in["document"])
	}
	if out != nil {
		b, _ := json.Marshal(reply)
		return json.Unmarshal(b, out)
	}
	return nil
}

func (w *world) ApplyNetwork(string) (bool, error) {
	w.log("сеть")
	if w.noRoles {
		return false, ErrNoRoles
	}
	if w.busy > 0 {
		w.busy--
		return false, ErrBusy
	}
	w.now = w.now.Add(w.slow)
	return w.awaiting, nil
}
func (w *world) ConfirmNetwork(string) error {
	w.log("окно закреплено")
	return w.confirmErr
}
func (w *world) CancelNetwork(string)        { w.log("окно отменено") }
func (w *world) ApplyServices(string) string { w.log("службы"); return "" }
func (w *world) ApplyTunnel() error          { w.log("канал"); return nil }
func (w *world) ConfirmTimeout() int         { return 120 }
func (w *world) Audit(event, _, _ string)    { w.log("журнал " + event) }
func (w *world) Cards() ([]CardFacts, error) { return w.cards, nil }
func (w *world) Get(k string) string         { return w.store[k] }
func (w *world) Set(k, v string) error       { w.store[k] = v; return nil }

func newWorld() (*world, *Importer) {
	w := &world{master: "on", mode: "black", now: time.Unix(1_000_000, 0), store: map[string]string{}}
	im := &Importer{Entries: w.entries(), Agent: w, System: w, Store: w,
		Version: func() string { return "0" }, Now: func() time.Time { return w.now }}
	return w, im
}

func file(t *testing.T, im *Importer, edit func(map[string]map[string]any)) *backupfile.Document {
	t.Helper()
	doc, err := backup.Build(im.Entries, backupfile.KindCopy, "0", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	obj := map[string]map[string]any{}
	for name, s := range doc.Sections {
		var m map[string]any
		_ = json.Unmarshal(s.Data, &m)
		obj[name] = m
	}
	edit(obj)
	for name, m := range obj {
		raw, _ := json.Marshal(m)
		s := doc.Sections[name]
		s.Data = raw
		doc.Sections[name] = s
	}
	return doc
}

func has(calls []string, want ...string) bool {
	j := 0
	for _, c := range calls {
		if j < len(want) && c == want[j] {
			j++
		}
	}
	return j == len(want)
}

func TestImportThenConfirm(t *testing.T) {
	w, im := newWorld()
	plan, err := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if err != nil {
		t.Fatal(err)
	}
	if awaiting, err := im.Apply("console", plan, nil, false); err != nil || awaiting {
		t.Fatalf("%v %v", awaiting, err)
	}
	if w.master != "off" || w.checkpoint == nil {
		t.Fatalf("раздел записан, точка возврата есть: %s %s", w.master, w.checkpoint)
	}
	if _, err := im.Confirm("console"); err != nil {
		t.Fatal(err)
	}
	if !has(w.calls, "backup.checkpoint", "запись metrics=off", "сеть", "канал", "backup.checkpoint_drop") || w.checkpoint != nil {
		t.Fatalf("порядок: %v", w.calls)
	}
	if w.store[SettingUntil] != "" {
		t.Fatalf("состояние импорта не очищено: %v", w.store)
	}
}

func TestWindowIsConfirmedWithImport(t *testing.T) {
	w, im := newWorld()
	w.awaiting = true
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if awaiting, err := im.Apply("192.168.11.2", plan, nil, false); err != nil || !awaiting {
		t.Fatalf("%v %v", awaiting, err)
	}
	if _, err := im.Confirm("192.168.11.2"); err != nil || !has(w.calls, "окно закреплено", "канал", "backup.checkpoint_drop") {
		t.Fatalf("%v %v", err, w.calls)
	}
}

func TestExpiredConfirmRollsBack(t *testing.T) {
	w, im := newWorld()
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(121 * time.Second)
	if _, err := im.Confirm("console"); err == nil || !strings.Contains(err.Error(), "срок") {
		t.Fatalf("подтверждение после срока: %v", err)
	}
	if w.master != "on" || w.checkpoint != nil {
		t.Fatalf("откат вернул раздел и убрал точку: %s %s", w.master, w.checkpoint)
	}
	if !has(w.calls, "backup.checkpoint_document", "backup.checkpoint_secrets", "запись metrics=on", "сеть", "канал", "backup.checkpoint_secrets", "backup.checkpoint_drop") {
		t.Fatalf("путь отката: %v", w.calls)
	}
}

func TestRollbackWithOpenWindowCancelsIt(t *testing.T) {
	w, im := newWorld()
	w.awaiting = true
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("192.168.11.2", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.calls = nil
	if _, err := im.Rollback("192.168.11.2"); err != nil {
		t.Fatal(err)
	}
	if !has(w.calls, "окно отменено", "службы", "канал") || has(w.calls, "сеть") {
		t.Fatalf("откат при открытом окне: %v", w.calls)
	}
}

func TestWriteFailureRollsBack(t *testing.T) {
	w, im := newWorld()
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	w.failWrite = true
	if _, err := im.Apply("console", plan, nil, false); err == nil || !strings.Contains(err.Error(), "откачен") {
		t.Fatalf("сбой записи: %v", err)
	}
	if w.checkpoint != nil || w.master != "on" {
		t.Fatalf("после сбоя — состояние до импорта: %s %s", w.master, w.checkpoint)
	}
}

func TestDangerNeedsConsentAndPendingRefused(t *testing.T) {
	w, im := newWorld()
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["vpn"]["mode"] = "white" }))
	if _, err := im.Apply("console", plan, nil, false); !errors.Is(err, ErrDanger) || w.checkpoint != nil {
		t.Fatalf("опасное без согласия: %v, точка %s", err, w.checkpoint)
	}
	if _, err := im.Apply("console", plan, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Apply("console", plan, nil, true); !errors.Is(err, ErrPending) {
		t.Fatalf("второй импорт поверх незавершённого: %v", err)
	}
}

func TestExportCopyAndTemplate(t *testing.T) {
	_, im := newWorld()
	raw, err := im.ExportCopy("KJ4Q-7NPM", "пароль")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := backupfile.Parse(raw)
	if err != nil || doc.Kind != backupfile.KindCopy || len(doc.Secrets) > 0 {
		t.Fatalf("агенту уходит копия без секретов: %v %+v", err, doc)
	}
	raw, err = im.ExportTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTemplate(raw); err != nil {
		t.Fatalf("шаблон не открывается как шаблон: %v", err)
	}
}

func TestCheckpointWithoutDeadlineIsExpired(t *testing.T) {
	w, im := newWorld()
	w.checkpoint = json.RawMessage(`{}`)
	if pending, expired, err := im.Pending(); err != nil || !pending || !expired {
		t.Fatalf("точка без срока: pending=%v expired=%v err=%v", pending, expired, err)
	}
}

func TestNetworkWindowConfirmedSeparately(t *testing.T) {
	w, im := newWorld()
	w.awaiting = true
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("192.168.11.2", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := im.ConfirmNetwork("192.168.11.2"); err != nil {
		t.Fatal(err)
	}
	if st := im.Current(); !st.Pending || st.Window {
		t.Fatalf("после окна сети импорт ждёт, окна нет: %+v", st)
	}
	w.calls = nil
	if _, err := im.Confirm("192.168.11.2"); err != nil || has(w.calls, "окно закреплено") {
		t.Fatalf("%v %v", err, w.calls)
	}
}

func TestExpireOnlyAfterDeadline(t *testing.T) {
	w, im := newWorld()
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	if done, err := im.Expire(); done || err != nil {
		t.Fatalf("до срока откатывать нечего: %v %v", done, err)
	}
	w.now = w.now.Add(121 * time.Second)
	if done, err := im.Expire(); !done || err != nil || w.master != "on" || !has(w.calls, "журнал settings_import_expired") {
		t.Fatalf("после срока — откат: %v %v %s %v", done, err, w.master, w.calls)
	}
	if done, _ := im.Expire(); done {
		t.Fatal("повторный такт: откатывать уже нечего")
	}
}

func TestLockHeldAndReleased(t *testing.T) {
	_, im := newWorld()
	held := 0
	im.Lock = func() (func(), error) { held++; return func() { held-- }, nil }
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Rollback("console"); err != nil || held != 0 {
		t.Fatalf("блокировка отпущена: %v held=%d", err, held)
	}
	im.Lock = func() (func(), error) { return nil, errors.New("занято") }
	if _, err := im.Confirm("console"); err == nil {
		t.Fatal("без блокировки изменения нет")
	}
}

func TestExportNotices(t *testing.T) {
	w, im := newWorld()
	if n := im.Notices(); len(n) != 1 || !strings.Contains(n[0].Text, "ещё нет") {
		t.Fatalf("копии нет: %+v", n)
	}
	im.MarkExported("192.168.11.2")
	if n := im.Notices(); len(n) != 1 || n[0].Level != "warn" || !strings.Contains(n[0].Text, "192.168.11.2") {
		t.Fatalf("свежая выгрузка: %+v", n)
	}
	w.now = w.now.Add(ExportNoticeFor + time.Hour)
	w.master = "off"
	if n := im.Notices(); len(n) != 1 || !strings.Contains(n[0].Text, "изменились") {
		t.Fatalf("после недели и правки: %+v", n)
	}
}

func TestConsoleExportNoticeSaysConsole(t *testing.T) {
	_, im := newWorld()
	im.MarkExported("")
	if n := im.Notices(); len(n) != 1 || !strings.Contains(n[0].Text, "с консоли шлюза") {
		t.Fatalf("%+v", n)
	}
}

func TestSlowApplyKeepsConfirmWindow(t *testing.T) {
	w, im := newWorld()
	w.slow = 110 * time.Second
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(60 * time.Second)
	if done, _ := im.Expire(); done {
		t.Fatal("импорт откачен раньше, чем у человека было окно на проверку")
	}
	if _, err := im.Confirm("console"); err != nil {
		t.Fatalf("подтверждение в окне: %v", err)
	}
}

func TestRollbackWithoutRolesLeavesNetwork(t *testing.T) {
	w, im := newWorld()
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.noRoles = true
	msg, err := im.Rollback("console")
	if err != nil || w.master != "on" || w.checkpoint != nil || !strings.Contains(msg, "сеть шлюза оставлена как есть") {
		t.Fatalf("откат без ролей: %q %v (master=%s)", msg, err, w.master)
	}
}

func TestRollbackWaitsWhileBusy(t *testing.T) {
	w, im := newWorld()
	var slept time.Duration
	im.Sleep = func(d time.Duration) { slept += d; w.now = w.now.Add(d) }
	plan, _ := im.Plan(file(t, im, func(o map[string]map[string]any) { o["metrics"]["master"] = "off" }))
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.busy = 3
	if _, err := im.Rollback("console"); err != nil || w.checkpoint != nil || slept != 7*time.Second {
		t.Fatalf("откат при занятой службе: %v, ждали %v", err, slept)
	}
	if _, err := im.Apply("console", plan, nil, false); err != nil {
		t.Fatal(err)
	}
	w.busy = 1000
	if _, err := im.Rollback("console"); !errors.Is(err, ErrBusy) {
		t.Fatalf("бесконечное ожидание: %v", err)
	}
}

func TestBrokenCheckpointIsDropped(t *testing.T) {
	for name, act := range map[string]func(*Importer) error{
		"срок":          func(im *Importer) error { _, err := im.Expire(); return err },
		"подтверждение": func(im *Importer) error { _, err := im.Confirm("console"); return err },
		"откат":         func(im *Importer) error { _, err := im.Rollback("console"); return err },
	} {
		w, im := newWorld()
		w.broken = true
		w.store[SettingUntil] = "1"
		if err := act(im); err != nil || w.broken || w.store[SettingUntil] != "" || !has(w.calls, "журнал settings_import_broken") {
			t.Fatalf("%s: %v broken=%v until=%q %v", name, err, w.broken, w.store[SettingUntil], w.calls)
		}
	}
}
