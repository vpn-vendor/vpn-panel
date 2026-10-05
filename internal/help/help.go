package help

import (
	"fmt"
	"regexp"
)

type Check string

const (
	CheckInternet Check = "internet"
	CheckChannel  Check = "channel"
	CheckPanel    Check = "panel"
)

var knownChecks = map[Check]bool{CheckInternet: true, CheckChannel: true, CheckPanel: true}

type Topic struct {
	Number   int
	Key      string
	Question string
	Checks   []Check

	Steps   []string
	Actions []string
	Section string
}

const maxNumber = 9

var topics = []Topic{
	{Number: 1, Key: "login", Question: "Не могу войти в панель",
		Checks: []Check{CheckPanel},
		Steps: []string{
			"Вход в панель — по коду подключения. Код одноразовый и действует недолго: получите новый и введите его сразу.",
			"Код выдаёт сам сервер или уже подключённое устройство на странице «Устройства». Устройство, добавленное недавно, первые часы выдавать коды не может.",
			"На сервере с рабочим столом код не нужен: откройте в списке программ значок «Вход в панель — с этого сервера».",
			"Предупреждение браузера о сертификате при первом входе с устройства — ожидаемо. Появилось внезапно на знакомом устройстве — не входите.",
		},
		Actions: []string{"code"}, Section: "devices"},
	{Number: 2, Key: "browser", Question: "Панель не открывается в браузере",
		Checks: []Check{CheckPanel},
		Steps: []string{
			"Проверьте адрес: его печатает сервер вместе с кодом входа.",
			"Компьютер должен быть в сети офиса, за шлюзом: из интернета панель не открывается.",
			"Панель остановлена или не отвечает — перезапустите её. Интернет в офисе и звонки при этом не прервутся.",
			"Не помогло — соберите сведения для поддержки.",
		},
		Actions: []string{"code", "restart", "support"}},
	{Number: 3, Key: "internet", Question: "В офисе нет интернета",
		Checks: []Check{CheckInternet, CheckChannel},
		Steps: []string{
			"Нет подключения к провайдеру — проверьте кабель провайдера и его оборудование, затем звоните провайдеру.",
			"Не работает защищённый канал — шлюз закрыл офис от интернета намеренно, чтобы ничего не ушло мимо канала. Что делать, сказано в подробном состоянии шлюза и на странице «Обзор».",
			"Связь нужна прямо сейчас — переставьте кабель провайдера и кабель сети офиса в прежний роутер.",
		},
		Actions: []string{"status", "support"}, Section: "home"},
	{Number: 4, Key: "calls", Question: "Интернет есть, а звонки плохие",
		Checks: []Check{CheckInternet, CheckChannel},
		Steps: []string{
			"Чаще всего дело в компьютере сотрудника или в сети офиса, а не в шлюзе. Страница «Диагностика» показывает, что не так с каждым компьютером, и даёт совет.",
			"На странице QoS укажите настоящую скорость тарифа: тогда звонки идут вперёд закачек. Сомневаетесь — укажите чуть меньше: завышенная скорость выключает эту защиту.",
			"Плохо у всех сразу — посмотрите «Обзор»: обрывы защищённого канала видны там.",
		},
		Actions: []string{"status"}, Section: "diagnostics"},
	{Number: 5, Key: "disk-password", Question: "Забыл пароль диска",
		Steps: []string{
			"Сначала проверьте ввод: пароль набирается в английской раскладке, клавиша Caps Lock выключена.",
			"Восстановить пароль диска нельзя: его не знает ни панель, ни поддержка.",
			"Пока шлюз включён и работает — не выключайте его и сделайте копию настроек на странице «Резервная копия». Копию храните вне шлюза.",
			"Дальше — установка шлюза с носителя заново и загрузка настроек из копии. Новый пароль диска задаётся при первом включении.",
		},
		Actions: []string{"backup"}, Section: "backup"},
	{Number: 6, Key: "lost-device", Question: "Потеряно устройство входа",
		Steps: []string{
			"Есть другое подключённое устройство — откройте на нём страницу «Устройства» и отзовите доступ у потерянного.",
			"Другого устройства нет — выйдите на всех устройствах с сервера и войдите заново по новому коду.",
			"Интернет в офисе, звонки и защищённый канал при этом не прерываются.",
		},
		Actions: []string{"signout", "code"}, Section: "devices"},
	{Number: 7, Key: "power", Question: "После отключения света",
		Checks: []Check{CheckInternet, CheckChannel, CheckPanel},
		Steps: []string{
			"Шлюз с зашифрованным диском после включения ждёт пароль диска — на экране и клавиатуре самого сервера. Пока пароль не введён, интернета в офисе нет.",
			"После пароля шлюз сам возвращается в сеть с прежними настройками. Изменение, которое не успели подтвердить до отключения, отменяется само.",
			"Что-то не заработало — причина и совет есть в подробном состоянии шлюза и на странице «Обзор».",
		},
		Actions: []string{"status"}, Section: "home"},
	{Number: 8, Key: "old-router", Question: "Хочу вернуть прежний роутер",
		Steps: []string{
			"Сделайте копию настроек на странице «Резервная копия» — она пригодится, если вернётесь к шлюзу.",
			"Переставьте кабель провайдера и кабель сети офиса обратно в прежний роутер: офис заработает как раньше.",
			"Компьютер, который не вышел в интернет сам, перезагрузите.",
			"Шлюз можно выключить: настройки на нём сохранятся.",
		},
		Actions: []string{"backup"}, Section: "backup"},
}

func Topics() []Topic { return append([]Topic(nil), topics...) }

func ByNumber(n int) (Topic, bool) {
	for _, t := range topics {
		if t.Number == n {
			return t, true
		}
	}
	return Topic{}, false
}

var keyName = regexp.MustCompile(`^[a-z][a-z-]*$`)

func Validate(list []Topic, action, section func(string) bool) error {
	numbers, keys := map[int]bool{}, map[string]bool{}
	previous := 0
	for _, t := range list {
		switch {
		case t.Number < 1 || t.Number > maxNumber:
			return fmt.Errorf("тема «%s»: цифра %d вне 1–%d", t.Question, t.Number, maxNumber)
		case numbers[t.Number]:
			return fmt.Errorf("цифра %d занята дважды", t.Number)
		case previous > t.Number:
			return fmt.Errorf("тема «%s» стоит не по порядку цифр", t.Question)
		case !keyName.MatchString(t.Key):
			return fmt.Errorf("тема «%s»: имя «%s» не латиницей", t.Question, t.Key)
		case keys[t.Key]:
			return fmt.Errorf("имя «%s» занято дважды", t.Key)
		case t.Question == "":
			return fmt.Errorf("тема %d без вопроса", t.Number)
		case len(t.Steps) == 0:
			return fmt.Errorf("тема «%s» ничего не советует", t.Question)
		case t.Section != "" && !section(t.Section):
			return fmt.Errorf("тема «%s»: раздела «%s» в панели нет", t.Question, t.Section)
		}
		for _, c := range t.Checks {
			if !knownChecks[c] {
				return fmt.Errorf("тема «%s»: проверки «%s» нет", t.Question, c)
			}
		}
		for _, a := range t.Actions {
			if !action(a) {
				return fmt.Errorf("тема «%s»: действия «%s» нет", t.Question, a)
			}
		}
		numbers[t.Number], keys[t.Key] = true, true
		previous = t.Number
	}
	return nil
}
