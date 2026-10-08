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

type Intent string

const (
	IntentCode    Intent = "code"
	IntentRestart Intent = "restart"
	IntentSupport Intent = "support"
	IntentBackup  Intent = "backup"
	IntentSignOut Intent = "signout"
)

var knownIntents = map[Intent]bool{IntentCode: true, IntentRestart: true, IntentSupport: true, IntentBackup: true, IntentSignOut: true}

type Topic struct {
	Key      string
	Question string
	Checks   []Check

	Steps    []string
	Intents  []Intent
	Section  string
	Keywords []string
}

var topics = []Topic{
	{Key: "login", Question: "Не могу войти в панель",
		Checks: []Check{CheckPanel},
		Steps: []string{
			"Вход в панель — по коду подключения. Код одноразовый и действует недолго: получите новый и введите его сразу.",
			"Код выдаёт сам сервер или уже подключённое устройство на странице «Устройства». Устройство, добавленное недавно, первые часы выдавать коды не может.",
			"На сервере с рабочим столом код не нужен: откройте в списке программ значок «Вход в панель — с этого сервера».",
			"Предупреждение браузера о сертификате при первом входе с устройства — ожидаемо. Появилось внезапно на знакомом устройстве — не входите.",
		},
		Intents: []Intent{IntentCode}, Section: "devices",
		Keywords: []string{"вход", "код", "не пускает", "доступ"}},
	{Key: "browser", Question: "Панель не открывается в браузере",
		Checks: []Check{CheckPanel},
		Steps: []string{
			"Проверьте адрес: его печатает сервер вместе с кодом входа.",
			"Компьютер должен быть в сети офиса, за шлюзом: из интернета панель не открывается.",
			"Панель остановлена или не отвечает — перезапустите её. Интернет в офисе и звонки при этом не прервутся.",
			"Не помогло — соберите сведения для поддержки.",
		},
		Intents:  []Intent{IntentCode, IntentRestart, IntentSupport},
		Keywords: []string{"браузер", "адрес", "не открывается", "не отвечает"}},
	{Key: "internet", Question: "В офисе нет интернета",
		Checks: []Check{CheckInternet, CheckChannel},
		Steps: []string{
			"Нет подключения к провайдеру — проверьте кабель провайдера и его оборудование, затем звоните провайдеру.",
			"Не работает защищённый канал — шлюз закрыл офис от интернета намеренно, чтобы ничего не ушло мимо канала. Что делать, сказано в подробном состоянии шлюза и на странице «Обзор».",
			"Связь нужна прямо сейчас — переставьте кабель провайдера и кабель сети офиса в прежний роутер.",
		},
		Intents: []Intent{IntentSupport}, Section: "home",
		Keywords: []string{"интернет", "связь", "нет сети", "не работает"}},
	{Key: "calls", Question: "Интернет есть, а звонки плохие",
		Checks: []Check{CheckInternet, CheckChannel},
		Steps: []string{
			"Чаще всего дело в компьютере сотрудника или в сети офиса, а не в шлюзе. Страница «Диагностика» показывает, что не так с каждым компьютером, и даёт совет.",
			"На странице QoS укажите настоящую скорость тарифа: тогда звонки идут вперёд закачек. Сомневаетесь — укажите чуть меньше: завышенная скорость выключает эту защиту.",
			"Плохо у всех сразу — посмотрите «Обзор»: обрывы защищённого канала видны там.",
		},
		Section:  "diagnostics",
		Keywords: []string{"звонки", "телефония", "voip", "качество", "обрывы"}},
	{Key: "disk-password", Question: "Забыл пароль диска",
		Steps: []string{
			"Сначала проверьте ввод: пароль набирается в английской раскладке, клавиша Caps Lock выключена.",
			"Восстановить пароль диска нельзя: его не знает ни панель, ни поддержка.",
			"Пока шлюз включён и работает — не выключайте его и сделайте копию настроек на странице «Резервная копия». Копию храните вне шлюза.",
			"Дальше — установка шлюза с носителя заново и загрузка настроек из копии. Новый пароль диска задаётся при первом включении.",
		},
		Intents: []Intent{IntentBackup}, Section: "backup",
		Keywords: []string{"диск", "пароль", "забыл", "шифрование"}},
	{Key: "lost-device", Question: "Потеряно устройство входа",
		Steps: []string{
			"Есть другое подключённое устройство — откройте на нём страницу «Устройства» и отзовите доступ у потерянного.",
			"Другого устройства нет — выйдите на всех устройствах с сервера и войдите заново по новому коду.",
			"Интернет в офисе, звонки и защищённый канал при этом не прерываются.",
		},
		Intents: []Intent{IntentSignOut, IntentCode}, Section: "devices",
		Keywords: []string{"потерял", "украли", "телефон", "ноутбук", "отозвать"}},
	{Key: "power", Question: "После отключения света",
		Checks: []Check{CheckInternet, CheckChannel, CheckPanel},
		Steps: []string{
			"Шлюз с зашифрованным диском после включения ждёт пароль диска — на экране и клавиатуре самого сервера. Пока пароль не введён, интернета в офисе нет.",
			"После пароля шлюз сам возвращается в сеть с прежними настройками. Изменение, которое не успели подтвердить до отключения, отменяется само.",
			"Что-то не заработало — причина и совет есть в подробном состоянии шлюза и на странице «Обзор».",
		},
		Section:  "home",
		Keywords: []string{"свет", "отключили", "электричество", "питание", "включение", "перезагрузка"}},
	{Key: "old-router", Question: "Хочу вернуть прежний роутер",
		Steps: []string{
			"Сделайте копию настроек на странице «Резервная копия» — она пригодится, если вернётесь к шлюзу.",
			"Переставьте кабель провайдера и кабель сети офиса обратно в прежний роутер: офис заработает как раньше.",
			"Компьютер, который не вышел в интернет сам, перезагрузите.",
			"Шлюз можно выключить: настройки на нём сохранятся.",
		},
		Intents: []Intent{IntentBackup}, Section: "backup",
		Keywords: []string{"роутер", "вернуть", "откат", "отключить шлюз"}},
}

func Topics() []Topic { return append([]Topic(nil), topics...) }

func ByKey(key string) (Topic, bool) {
	for _, t := range topics {
		if t.Key == key {
			return t, true
		}
	}
	return Topic{}, false
}

var keyName = regexp.MustCompile(`^[a-z][a-z-]*$`)

func Validate(list []Topic, section func(string) bool) error {
	keys := map[string]bool{}
	for _, t := range list {
		switch {
		case !keyName.MatchString(t.Key):
			return fmt.Errorf("тема «%s»: имя «%s» не латиницей", t.Question, t.Key)
		case keys[t.Key]:
			return fmt.Errorf("имя «%s» занято дважды", t.Key)
		case t.Question == "":
			return fmt.Errorf("тема «%s» без вопроса", t.Key)
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
		for _, i := range t.Intents {
			if !knownIntents[i] {
				return fmt.Errorf("тема «%s»: намерения «%s» нет", t.Question, i)
			}
		}
		keys[t.Key] = true
	}
	return nil
}
