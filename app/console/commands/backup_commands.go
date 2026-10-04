package commands

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"os"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

var ageHeader = []byte("age-encryption.org/v1")

const consoleIP = ""

func openFile(im *restore.Importer, path string) (*backupfile.Document, *restore.Secrets, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, nil, err
	}
	if !bytes.HasPrefix(data, ageHeader) {
		doc, err := restore.OpenTemplate(data)
		return doc, nil, err
	}
	fmt.Fprintln(os.Stderr, "Пароль копии (одной строкой в стандартный ввод):")
	pass := readLine(bufio.NewReader(os.Stdin))
	if pass == "" {
		return nil, nil, &restore.Refusal{Text: "пароль копии не получен"}
	}
	doc, inv, err := im.OpenCopy(data, pass)
	if err != nil {
		return nil, nil, err
	}
	return doc, &restore.Secrets{File: data, Password: pass, Restore: inv}, nil
}

var cardFlag = &command.StringSliceFlag{Name: "card", Usage: "карта из файла = карта этого шлюза (для копии с другого железа)"}

func choice(ctx console.Context) map[string]string {
	out := map[string]string{}
	for _, v := range ctx.OptionSlice("card") {
		if from, to, ok := strings.Cut(v, "="); ok {
			out[strings.TrimSpace(from)] = strings.TrimSpace(to)
		}
	}
	return out
}

func printPreview(pv *restore.Preview, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(pv.Plan)
		fmt.Println(string(b))
		return
	}
	if len(pv.Ask) > 0 {
		fmt.Println("  Карты из файла, которых нет на этом шлюзе (назначьте: --card карта-из-файла=карта-здесь):")
		for _, r := range pv.Ask {
			fmt.Printf("      %s (роль %s)\n", r.Card.Name, r.Field("role"))
		}
		fmt.Println("  Карты этого шлюза:")
		for _, c := range pv.Cards {
			facts := []string{"кабеля нет"}
			if c.Link {
				facts = []string{"кабель есть"}
			}
			if c.SpeedMbit > 0 {
				facts = append(facts, fmt.Sprintf("%d Мбит/с", c.SpeedMbit))
			}
			if c.Provider {
				facts = append(facts, "провайдер ответил")
			}
			fmt.Printf("      %s %s: %s\n", c.Name, c.MAC, strings.Join(facts, ", "))
		}
	}
	for _, h := range pv.Hints {
		fmt.Println("  ВНИМАНИЕ: " + h)
	}
	printPlan(pv.Plan)
}

func printPlan(p *backup.Plan) {
	for _, s := range p.Sections {
		switch {
		case !s.InFile:
			fmt.Printf("  %s: нет в файле — не трогается\n", s.Name)
		case len(s.Changes) == 0:
			fmt.Printf("  %s: останется как есть\n", s.Name)
		default:
			fmt.Printf("  %s: изменится\n", s.Name)
			for _, c := range s.Changes {
				mark := ""
				if c.Dangerous {
					mark = "  ← ОПАСНО: " + c.Title + " — " + c.Warn
				}
				fmt.Printf("      %s (%s)%s\n", c.Path, c.Kind, mark)
			}
		}
		if len(s.NotTransferred) > 0 {
			fmt.Printf("      не переносится: %s\n", strings.Join(s.NotTransferred, ", "))
		}
	}
	for _, e := range p.Errors {
		fmt.Println("  ОШИБКА: " + e)
	}
}

func consoleImporter() *restore.Importer {
	return restore.Console(func(wait time.Duration) {
		fmt.Fprintf(os.Stderr, "Системная служба просит подождать %d с — жду и повторяю.\n", int(wait/time.Second))
	})
}

func human(err error) error { return errors.New(restore.Text(err)) }

type BackupExport struct{}

func (c *BackupExport) Signature() string { return "backup:export" }
func (c *BackupExport) Description() string {
	return "Выгрузить настройки в файл: копию или шаблон (консоль сервера)"
}
func (c *BackupExport) Extend() command.Extend {
	return command.Extend{ArgsUsage: "<файл>", Flags: []command.Flag{
		&command.BoolFlag{Name: "template", Usage: "шаблон без секретов и без привязки к шлюзу"}}}
}

func (c *BackupExport) Handle(ctx console.Context) error {
	im := consoleImporter()
	var (
		data []byte
		err  error
	)
	if ctx.OptionBool("template") {
		data, err = im.ExportTemplate()
	} else {
		fmt.Fprintln(os.Stderr, "Код с экрана шлюза и пароль копии — две строки стандартного ввода:")
		in := bufio.NewReader(os.Stdin)
		code, pass := readLine(in), readLine(in)
		if code == "" || pass == "" {
			return &restore.Refusal{Text: "нужны код и пароль копии"}
		}
		if data, err = im.ExportCopy(code, pass); err == nil {
			im.System.Audit("settings_export", consoleIP, "выгружена полная копия настроек с консоли")
			im.MarkExported(consoleIP)
		}
	}
	if err != nil {
		return human(err)
	}
	if err := durable.Write(ctx.Argument(0), data, 0o600); err != nil {
		return human(err)
	}
	fmt.Printf("Записано: %d байт\n", len(data))
	return nil
}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

type BackupPlan struct{}

func (c *BackupPlan) Signature() string { return "backup:plan" }
func (c *BackupPlan) Description() string {
	return "План импорта настроек из файла, без записи (консоль сервера)"
}
func (c *BackupPlan) Extend() command.Extend {
	return command.Extend{ArgsUsage: "<файл>", Flags: []command.Flag{&command.BoolFlag{Name: "json", Usage: "план одним объектом JSON"}, cardFlag}}
}

func (c *BackupPlan) Handle(ctx console.Context) error {
	im := consoleImporter()
	doc, _, err := openFile(im, ctx.Argument(0))
	if err != nil {
		return human(err)
	}
	pv, err := im.Preview(doc, choice(ctx))
	if err != nil {
		return human(err)
	}
	printPreview(pv, ctx.OptionBool("json"))
	return nil
}

type BackupImport struct{}

func (c *BackupImport) Signature() string { return "backup:import" }
func (c *BackupImport) Description() string {
	return "Применить настройки из файла; затем backup:confirm или backup:rollback (консоль сервера)"
}
func (c *BackupImport) Extend() command.Extend {
	return command.Extend{ArgsUsage: "<файл>", Flags: []command.Flag{
		&command.BoolFlag{Name: "accept-danger", Usage: "принять опасные изменения плана"}, cardFlag}}
}

func (c *BackupImport) Handle(ctx console.Context) error {
	im := consoleImporter()
	doc, sec, err := openFile(im, ctx.Argument(0))
	if err != nil {
		return human(err)
	}
	pv, err := im.Preview(doc, choice(ctx))
	if err != nil {
		return human(err)
	}
	printPreview(pv, false)
	awaiting, err := im.Apply(consoleIP, pv.Plan, sec, ctx.OptionBool("accept-danger"))
	if err != nil {
		return human(err)
	}
	if awaiting {
		fmt.Println("Сеть применена с окном подтверждения.")
	}
	fmt.Println("Проверьте работу и выполните backup:confirm; без подтверждения в срок — backup:rollback вернёт прежние настройки.")
	return nil
}

type BackupConfirm struct{}

func (c *BackupConfirm) Signature() string { return "backup:confirm" }
func (c *BackupConfirm) Description() string {
	return "Закрепить импорт настроек (консоль сервера)"
}
func (c *BackupConfirm) Extend() command.Extend { return command.Extend{} }
func (c *BackupConfirm) Handle(console.Context) error {
	msg, err := consoleImporter().Confirm(consoleIP)
	if err != nil {
		return human(err)
	}
	fmt.Println(msg)
	return nil
}

type BackupRollback struct{}

func (c *BackupRollback) Signature() string { return "backup:rollback" }
func (c *BackupRollback) Description() string {
	return "Откатить импорт настроек (консоль сервера)"
}
func (c *BackupRollback) Extend() command.Extend { return command.Extend{} }
func (c *BackupRollback) Handle(console.Context) error {
	msg, err := consoleImporter().Rollback(consoleIP)
	if err != nil {
		return human(err)
	}
	fmt.Println(msg)
	return nil
}

type BackupStatus struct{}

func (c *BackupStatus) Signature() string { return "backup:status" }
func (c *BackupStatus) Description() string {
	return "Состояние импорта настроек (консоль сервера)"
}
func (c *BackupStatus) Extend() command.Extend { return command.Extend{} }
func (c *BackupStatus) Handle(console.Context) error {
	pending, expired, err := consoleImporter().Pending()
	switch {
	case err != nil:
		return human(err)
	case !pending:
		fmt.Println("Незавершённого импорта нет.")
	case expired:
		fmt.Println("Импорт не подтверждён, срок истёк — выполните backup:rollback.")
	default:
		fmt.Println("Импорт ждёт подтверждения: backup:confirm или backup:rollback.")
	}
	return nil
}
