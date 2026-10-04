package supportfmt

const (
	smallPart   = 400
	tablePart   = 4000
	journalPart = 20000
)

type Source int

const (
	FromSystem Source = iota

	FromPanel
)

type Part struct {
	Section
	Source Source
}

var Parts = []Part{
	{Section{ID: "versions", Title: "Версии", MaxLines: smallPart}, FromSystem},
	{Section{ID: "hardware", Title: "Железо шлюза", MaxLines: smallPart}, FromSystem},
	{Section{ID: "links", Title: "Сетевые карты, адреса, маршруты, счётчики ошибок", MaxLines: tablePart}, FromSystem},
	{Section{ID: "neighbours", Title: "Соседи шлюза в сети офиса", MaxLines: tablePart}, FromSystem},
	{Section{ID: "status", Title: "Состояние сети, защиты, канала, QoS, обновлений и диска", MaxLines: tablePart}, FromSystem},
	{Section{ID: "firewall", Title: "Действующие правила защиты", MaxLines: tablePart}, FromSystem},
	{Section{ID: "services", Title: "Службы шлюза: работают ли и почему нет", MaxLines: tablePart}, FromSystem},
	{Section{ID: "journal-agent", Title: "Журнал системной службы панели", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-panel", Title: "Журнал панели", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-channel", Title: "Журнал канала VPN", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-network", Title: "Журнал сети", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-provider", Title: "Журнал подключения к провайдеру", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-dhcp", Title: "Журнал DHCP", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-dns", Title: "Журнал DNS", MaxLines: journalPart}, FromSystem},
	{Section{ID: "journal-kernel", Title: "Сообщения ядра", MaxLines: journalPart}, FromSystem},
	{Section{ID: "panel-events", Title: "Журнал событий панели", MaxLines: journalPart}, FromPanel},
	{Section{ID: "panel-settings", Title: "Настройки панели без секретов", MaxLines: tablePart}, FromPanel},
}

func Known() Set {
	list := make([]Section, len(Parts))
	for i, p := range Parts {
		list[i] = p.Section
	}
	set, err := NewSet(list...)
	if err != nil {
		panic(err)
	}
	return set
}
