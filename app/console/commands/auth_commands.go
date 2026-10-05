package commands

import (
	"fmt"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/internal/bindset"
)

type AuthCode struct{}

func (c *AuthCode) Signature() string { return "auth:code" }
func (c *AuthCode) Description() string {
	return "Выдать одноразовый код подключения устройства (консоль сервера)"
}
func (c *AuthCode) Extend() command.Extend { return command.Extend{} }

func (c *AuthCode) Handle(ctx console.Context) error {
	service := auth.New()
	if !service.HasUsers() {
		code, err := service.SetSetupCode()
		if err != nil {
			return err
		}
		fmt.Println("Учётных записей ещё нет — панель в режиме первичной установки.")
		fmt.Println("Установочный код (15 минут, ввести на странице мастера из локальной сети):")
		fmt.Println()
		fmt.Println("    " + code)
		fmt.Println()
		printPanelAddresses()
		return nil
	}

	userName := ctx.Argument(0)
	var user models.User
	if userName != "" {
		if err := facades.Orm().Query().Where("name", userName).Where("is_active", true).First(&user); err != nil || user.ID == 0 {
			return fmt.Errorf("учётная запись %q не найдена", userName)
		}
	} else {
		var users []models.User
		if err := facades.Orm().Query().Where("is_active", true).Find(&users); err != nil {
			return err
		}
		switch len(users) {
		case 0:
			return fmt.Errorf("нет активных учётных записей")
		case 1:
			user = users[0]
		default:
			return fmt.Errorf("учётных записей несколько — укажите имя: auth:code <имя>")
		}
	}

	code, err := service.IssueCode(user.ID, auth.ViaConsole, nil, "console")
	if err != nil {
		return err
	}
	ttl := service.SettingInt(auth.SettingCodeTTLMinutes)
	fmt.Printf("Код подключения для «%s» (%d минут, одноразовый):\n\n    %s\n\n", user.Name, ttl, code)
	fmt.Println("Введите его на странице входа панели. Никому не сообщайте код.")
	fmt.Println()
	fmt.Println("Если у сервера есть рабочий стол, код вводить не нужно:")
	fmt.Println("откройте список программ, наберите «вход в панель» и нажмите значок")
	fmt.Println("«Вход в панель — с этого сервера» — панель откроется сразу,")
	fmt.Println("система только спросит пароль администратора этого компьютера.")
	fmt.Println()
	printPanelAddresses()
	return nil
}

func printPanelAddresses() {
	port := facades.Config().GetString("http.tls.port")
	suffix := ""
	if port != "" && port != "443" {
		suffix = ":" + port
	}
	set := bindset.Compute(false, network.New().AppliedLANs(), bindset.LocalInterfaces())
	printed := 0
	for _, a := range set.Addrs {
		if a.IP == bindset.Loopback {
			continue
		}
		if printed == 0 {
			fmt.Println("Панель открыта из локальной сети по адресам:")
		}
		fmt.Printf("    https://%s%s   (карта %s)\n", a.IP, suffix, a.Iface)
		printed++
	}
	if printed == 0 {
		fmt.Println("Из локальной сети панель пока недоступна: у сетевых карт нет локального адреса.")
		fmt.Println("Подключите карту локальной сети к сети офиса (или кабелем к своему компьютеру)")
		fmt.Println("и повторите команду. С самого сервера панель открыта по https://127.0.0.1" + suffix)
	}
	if set.Mode == bindset.ModePreRoles && printed > 0 {
		fmt.Println("После назначения ролей сетевых карт панель останется только в локальной сети.")
	}
}

type AuthDesktopLogin struct{}

func (c *AuthDesktopLogin) Signature() string { return "auth:desktop-login" }
func (c *AuthDesktopLogin) Description() string {
	return "Выдать адрес входа с кодом для рабочего стола сервера"
}
func (c *AuthDesktopLogin) Extend() command.Extend { return command.Extend{} }

func (c *AuthDesktopLogin) Handle(console.Context) error {
	service := auth.New()
	if !service.HasUsers() {
		code, err := service.SetSetupCode()
		if err != nil {
			return err
		}
		fmt.Println(localPanelURL("/setup?code=" + code))
		fmt.Println(code)
		return nil
	}

	var users []models.User
	if err := facades.Orm().Query().Where("is_active", true).Find(&users); err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("нет активных учётных записей")
	}

	code, err := service.IssueCode(users[0].ID, auth.ViaConsole, nil, "desktop")
	if err != nil {
		return err
	}
	fmt.Println(localPanelURL("/login?code=" + code))
	fmt.Println(code)
	return nil
}

func localPanelURL(path string) string {
	port := facades.Config().GetString("http.tls.port")
	host := "127.0.0.1"
	if port != "" && port != "443" {
		host += ":" + port
	}
	return "https://" + host + path
}

type AuthReset struct{}

func (c *AuthReset) Signature() string { return "auth:reset" }
func (c *AuthReset) Description() string {
	return "Отозвать ВСЕ доверенные устройства (полный сброс доступа)"
}
func (c *AuthReset) Extend() command.Extend { return command.Extend{} }

func (c *AuthReset) Handle(ctx console.Context) error {
	service := auth.New()
	n, err := service.RevokeAll("полный сброс с консоли")
	if err != nil {
		return err
	}
	fmt.Printf("Отозвано устройств: %d. Сеть и звонки НЕ затронуты.\n", n)
	fmt.Println("Новый код подключения: auth:code")
	return nil
}
