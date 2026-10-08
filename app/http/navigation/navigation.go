package navigation

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/vpn-vendor/vpn-panel-core/internal/help"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

type Section struct {
	Key      string
	Title    string
	Subtitle string
	URL      string
	Icon     string
	Group    string
	Width    Width
}

type Width string

const (
	Narrow Width = "narrow"

	Wide Width = "wide"

	Full Width = "full"
)

func (w Width) Valid() bool { return w == Narrow || w == Wide || w == Full }

func WidthFor(key string) Width {
	if s, ok := SectionByKey(key); ok && s.Width.Valid() {
		return s.Width
	}
	return Narrow
}

type Entry struct {
	Title    string
	Hint     string
	URL      string
	Section  string
	Keywords []string
}

const MaxResults = 12

const MaxQueryRunes = 64

var sections = []Section{
	{Key: "home", Title: "Обзор", Subtitle: "Что сейчас со шлюзом", URL: "/", Icon: "home", Width: Wide},

	{Key: "network", Title: "Сеть", Subtitle: "Карты, адреса, провайдер", URL: "/network", Icon: "network", Group: "Сеть офиса", Width: Wide},
	{Key: "dhcp", Title: "DHCP", Subtitle: "Раздача адресов устройствам", URL: "/dhcp", Icon: "dhcp", Group: "Сеть офиса", Width: Wide},
	{Key: "dns", Title: "DNS", Subtitle: "Имена вместо адресов", URL: "/dns", Icon: "dns", Group: "Сеть офиса", Width: Narrow},
	{Key: "qos", Title: "QoS", Subtitle: "Приоритет разговоров", URL: "/qos", Icon: "qos", Group: "Сеть офиса", Width: Narrow},

	{Key: "vpn", Title: "VPN", Subtitle: "Защищённый канал офиса", URL: "/vpn", Icon: "vpn", Group: "Защита и доступ", Width: Wide},
	{Key: "security", Title: "Защита", Subtitle: "Невидимость и обновления", URL: "/security", Icon: "shield", Group: "Защита и доступ", Width: Wide},
	{Key: "devices", Title: "Устройства", Subtitle: "Доступ к панели и журнал", URL: "/devices", Icon: "devices", Group: "Защита и доступ", Width: Wide},
	{Key: "backup", Title: "Резервная копия", Subtitle: "Копия и перенос настроек", URL: "/backup", Icon: "backup", Group: "Защита и доступ", Width: Narrow},

	{Key: "diagnostics", Title: "Диагностика", Subtitle: "Проверки и их результат", URL: "/diagnostics", Icon: "diagnostics", Group: "Проверки", Width: Wide},
	{Key: "help", Title: "Помощь", Subtitle: "Что делать, если…", URL: "/help", Icon: "help", Group: "Проверки", Width: Narrow},
}

var entries = []Entry{
	{Title: "Роли сетевых карт", Hint: "Какая карта смотрит в интернет, а какая — в офис", URL: "/network", Section: "network",
		Keywords: []string{"wan", "lan", "карта", "интерфейс", "роль", "ens"}},
	{Title: "Подключение к провайдеру", Hint: "Автоматически, статический адрес или логин и пароль", URL: "/network", Section: "network",
		Keywords: []string{"pppoe", "static", "dhcp", "статика", "шлюз", "маска", "логин", "пароль", "провайдер", "ip"}},
	{Title: "Тег VLAN", Hint: "Только если провайдер его требует", URL: "/network", Section: "network",
		Keywords: []string{"vlan", "тег", "802.1q"}},

	{Title: "Аренды адресов", Hint: "Какому устройству какой адрес выдан", URL: "/dhcp", Section: "dhcp",
		Keywords: []string{"аренда", "lease", "адрес", "ip", "mac"}},
	{Title: "Закрепить адрес за устройством", Hint: "Постоянный адрес для принтера или телефона", URL: "/dhcp", Section: "dhcp",
		Keywords: []string{"резерв", "reserve", "постоянный", "закрепить", "статический"}},
	{Title: "Заполненность пулов", Hint: "Хватит ли адресов на все устройства", URL: "/dhcp", Section: "dhcp",
		Keywords: []string{"пул", "pool", "адреса кончились"}},

	{Title: "Имя панели в локальной сети", Hint: "Открывать панель по имени вместо адреса", URL: "/dns", Section: "dns",
		Keywords: []string{"vpn.lan", "домен", "имя", "resolver", "резолвер"}},

	{Title: "Скорость тарифа", Hint: "Чтобы звонки шли вперёд закачек", URL: "/qos", Section: "qos",
		Keywords: []string{"скорость", "тариф", "мбит", "cake", "телефония", "voip", "звонки"}},
	{Title: "Замер скорости интернета", Hint: "Узнать настоящую скорость подключения", URL: "/qos", Section: "qos",
		Keywords: []string{"speedtest", "замер", "скорость"}},

	{Title: "Загрузить файл подключения", Hint: "Файл от поставщика VPN", URL: "/vpn", Section: "vpn",
		Keywords: append(vpnproto.Keywords(), "профиль", "файл", "импорт")},
	{Title: "Режим трафика офиса", Hint: "Всё через канал или напрямую при сбое", URL: "/vpn", Section: "vpn",
		Keywords: []string{"kill switch", "режим", "напрямую", "защищённый"}},
	{Title: "Проверить защищённый канал", Hint: "Потери, задержка и скорость через канал", URL: "/vpn", Section: "vpn",
		Keywords: []string{"проверка", "потери", "задержка", "пинг", "check"}},
	{Title: "Размер пакетов", Hint: "Когда сайты открываются и зависают", URL: "/vpn", Section: "vpn",
		Keywords: []string{"mtu", "пакет", "фрагментация"}},
	{Title: "Проверить время сервера", Hint: "Когда поставщик отклоняет сертификаты", URL: "/vpn", Section: "vpn",
		Keywords: []string{"время", "часы", "ntp", "сертификат"}},

	{Title: "Невидимость из интернета", Hint: "Шлюз не отвечает на запросы снаружи", URL: "/security", Section: "security",
		Keywords: []string{"скрытый", "stealth", "невидимость", "ping", "firewall"}},
	{Title: "Автоматические обновления", Hint: "Панель обновляется сама", URL: "/security", Section: "security",
		Keywords: []string{"обновление", "update", "версия"}},
	{Title: "Пароль диска", Hint: "Шифрование диска и смена пароля при включении", URL: "/security", Section: "security",
		Keywords: []string{"шифрование", "диск", "пароль", "luks", "encryption"}},

	{Title: "Выдать код входа", Hint: "Пустить новое устройство в панель", URL: "/devices", Section: "devices",
		Keywords: []string{"код", "вход", "доступ", "устройство", "login"}},
	{Title: "Журнал безопасности", Hint: "Кто и когда входил в панель", URL: "/devices", Section: "devices",
		Keywords: []string{"журнал", "log", "вход", "аудит"}},

	{Title: "Выгрузить копию настроек", Hint: "Всё, включая ключи, в зашифрованном файле", URL: "/backup", Section: "backup",
		Keywords: []string{"копия", "backup", "резервная", "выгрузить", "экспорт", "сохранить"}},
	{Title: "Восстановить настройки из файла", Hint: "Вернуть шлюз или перенести его на новое железо", URL: "/backup", Section: "backup",
		Keywords: []string{"восстановить", "restore", "импорт", "загрузить", "перенос", "шаблон"}},

	{Title: "Проверить сеть офиса", Hint: "Потери и задержка до каждого устройства", URL: "/diagnostics", Section: "diagnostics",
		Keywords: []string{"проверка", "потери", "задержка", "устройства", "сеть"}},
}

func helpEntries() []Entry {
	out := make([]Entry, 0, len(help.Topics()))
	for _, t := range help.Topics() {
		out = append(out, Entry{Title: t.Question, Hint: "Помощь: что проверить и что делать", URL: "/help#" + t.Key,
			Section: "help", Keywords: t.Keywords})
	}
	return out
}

func Entries() []Entry { return append(append([]Entry(nil), entries...), helpEntries()...) }

func Sections() []Section { return sections }

type Group struct {
	Title    string
	Sections []Section
}

func Groups() []Group {
	var out []Group
	index := map[string]int{}
	for _, s := range sections {
		i, ok := index[s.Group]
		if !ok {
			i = len(out)
			index[s.Group] = i
			out = append(out, Group{Title: s.Group})
		}
		out[i].Sections = append(out[i].Sections, s)
	}
	return out
}

func SectionByKey(key string) (Section, bool) {
	for _, s := range sections {
		if s.Key == key {
			return s, true
		}
	}
	return Section{}, false
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "ё", "е")
	return strings.Join(strings.Fields(s), " ")
}

func Search(query string) []Entry {
	if utf8.RuneCountInString(query) > MaxQueryRunes {
		query = string([]rune(query)[:MaxQueryRunes])
	}
	q := normalize(query)
	if q == "" {
		return nil
	}
	words := strings.Fields(q)

	type scored struct {
		entry Entry
		score int
		order int
	}
	var found []scored
	order := 0
	consider := func(e Entry) {
		order++
		title := normalize(e.Title)
		rest := normalize(e.Hint + " " + strings.Join(e.Keywords, " "))
		score := 0
		for _, w := range words {
			switch {
			case strings.HasPrefix(title, w):
				score += 3
			case strings.Contains(title, w):
				score += 2
			case strings.Contains(rest, w):
				score++
			default:
				return
			}
		}
		found = append(found, scored{entry: e, score: score, order: order})
	}

	for _, s := range sections {
		consider(Entry{Title: s.Title, Hint: s.Subtitle, URL: s.URL, Section: s.Key})
	}
	for _, e := range Entries() {
		consider(e)
	}

	sort.SliceStable(found, func(i, j int) bool {
		if found[i].score != found[j].score {
			return found[i].score > found[j].score
		}
		return found[i].order < found[j].order
	})
	if len(found) > MaxResults {
		found = found[:MaxResults]
	}
	out := make([]Entry, len(found))
	for i, f := range found {
		out[i] = f.entry
	}
	return out
}
