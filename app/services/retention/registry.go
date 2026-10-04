package retention

type Kind string

const (
	Table   Kind = "таблица"
	File    Kind = "файл"
	Memory  Kind = "память"
	Journal Kind = "журнал"
)

type Class string

const (
	Critical Class = "критичное"
	Ordinary Class = "обычное"
	Cache    Class = "кэш"
	Unused   Class = "не используется"
)

type Growth string

const (
	ByNetwork Growth = "сеть"
	ByAdmin   Growth = "администратор"
	ByCode    Growth = "код"
	ByTime    Growth = "время"
)

type Ceiling struct {
	Name      string
	Kind      Kind
	Class     Class
	Growth    Growth
	Limit     string
	Age       string
	OnCeiling string
	Enforced  bool
	Debt      string
}

var FrameworkTables = []string{"migrations"}

var Declared = []Ceiling{

	{Name: "users", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "учётные записи создаются только консольными командами администратора", Age: "бессрочно",
		OnCeiling: "поток запросов из сети строк не создаёт", Enforced: true},
	{Name: "trusted_devices", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "строка на устройство, подключённое кодом администратора; без кода строк не создаётся", Age: "мёртвые доверия (отозваны, истёк простой или потолок) удаляются через 30 дней, администратор меняет в границах 7–365",
		OnCeiling: "уборка порциями по 1000 строк раз в минуту", Enforced: true},
	{Name: "enroll_codes", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "строка на код, выданный с консоли или с доверенного устройства", Age: "истёкшие удаляются через 90 дней",
		OnCeiling: "уборка порциями по 1000 строк раз в минуту", Enforced: true},
	{Name: "auth_events", Kind: Table, Class: Critical, Growth: ByNetwork,
		Limit: "обычных (вызываемых без входа) не больше 50 000, критичных не больше 20 000, системных — число системных кодов × 1440 × 7 суток; одинаковые обычные и системные — одна строка в минуту со счётчиком", Age: "90 дней, администратор меняет в границах 30–365",
		OnCeiling: "удаляются самые старые своего класса порциями по 1000 строк не дольше 1 с за проход; поток обычных и системных не вытесняет критичные",
		Enforced:  true},
	{Name: "settings", Kind: Table, Class: Critical, Growth: ByCode,
		Limit: "строка на ключ настройки; набор ключей задан кодом", Age: "бессрочно",
		OnCeiling: "запись заменяет значение ключа", Enforced: true},
	{Name: "interfaces", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "строка на сетевую карту шлюза", Age: "бессрочно",
		OnCeiling: "роли назначает администратор", Enforced: true},
	{Name: "dhcp_reservations", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "закрепления вносит администратор, адреса ограничены диапазоном закреплений", Age: "до удаления администратором",
		OnCeiling: "поток запросов из сети строк не создаёт", Enforced: true},
	{Name: "vpn_profiles", Kind: Table, Class: Critical, Growth: ByAdmin,
		Limit: "строка на файл подключения, загруженный администратором", Age: "до удаления администратором",
		OnCeiling: "поток запросов из сети строк не создаёт", Enforced: true},
	{Name: "boots", Kind: Table, Class: Ordinary, Growth: ByTime,
		Limit: "одна строка на загрузку сервера; аварийные перезапуски панели — поле строки, а не новые строки", Age: "8 суток (неделя счётчиков надёжности плюс сутки)",
		OnCeiling: "уборка порциями по 1000 строк раз в минуту; строка текущей загрузки не удаляется", Enforced: true},
	{Name: "vpn_checks", Kind: Table, Class: Ordinary, Growth: ByTime,
		Limit: "последние 50 прогонов проверки канала", Age: "вытесняются новыми",
		OnCeiling: "самые старые удаляются при записи нового", Enforced: true},
	{Name: "devices", Kind: Table, Class: Ordinary, Growth: ByNetwork,
		Limit: "не больше 256 новых паспортов в час; показ страницы пишет паспорт не чаще раза в минуту на устройство", Age: "неподписанные со случайным MAC забываются через 30 дней (администратор меняет в границах 7–365); подписанные хранятся",
		OnCeiling: "сверх предела новое устройство показывается без паспорта, одна сводная запись в журнале",
		Enforced:  true},
	{Name: "jobs", Kind: Table, Class: Unused, Growth: ByCode,
		Limit: "очередь фреймворка в режиме sync — строк не бывает", Age: "—",
		OnCeiling: "не применимо", Enforced: true},
	{Name: "failed_jobs", Kind: Table, Class: Unused, Growth: ByCode,
		Limit: "очередь фреймворка в режиме sync — строк не бывает", Age: "—",
		OnCeiling: "не применимо", Enforced: true},
	{Name: "migrations", Kind: Table, Class: Critical, Growth: ByCode,
		Limit: "строка на миграцию в коде", Age: "бессрочно",
		OnCeiling: "растёт только с новой версией пакета", Enforced: true},

	{Name: "/var/lib/vpn-panel/panel.sqlite-wal", Kind: File, Class: Ordinary, Growth: ByTime,
		Limit: "journal_size_limit 64 МБ: после контрольной точки файл укорачивается до предела", Age: "до контрольной точки (автоматически каждые 1000 страниц)",
		OnCeiling: "SQLite укорачивает файл; долгих читателей у панели нет",
		Enforced:  true},
	{Name: "данные панели целиком (/var/lib/vpn-panel)", Kind: File, Class: Ordinary, Growth: ByTime,
		Limit: "бюджет диска: по умолчанию 2 ГиБ, администратор меняет от 256 МиБ до потолка min(10 % диска, свободно + занято нами − max(15 % диска, 2 ГиБ), 10 ГиБ)", Age: "потолок пересчитывается каждые 10 с, растёт только после двух проверок подряд",
		OnCeiling: "уборка сокращает историю первой: срок журнала к нижней границе, потолок обычных событий 10 000; критичные события не трогаются", Enforced: true},
	{Name: "/var/lib/vpn-panel/agent-watchdog.json", Kind: File, Class: Critical, Growth: ByCode,
		Limit: "один файл сторожа канала фиксированной структуры, пишет агент", Age: "перезаписывается",
		OnCeiling: "запись заменяет содержимое", Enforced: true},
	{Name: "/var/lib/vpn-panel/panel.sqlite.bak-*", Kind: File, Class: Critical, Growth: ByCode,
		Limit: "последние 5 копий базы, делаются при обновлении пакета", Age: "вытесняются новыми",
		OnCeiling: "postinst удаляет копии старше пятой", Enforced: true},
	{Name: "/var/lib/vpn-panel/tls/{cert,key}.pem", Kind: File, Class: Critical, Growth: ByCode,
		Limit: "одна пара", Age: "до перевыпуска",
		OnCeiling: "перевыпуск заменяет пару", Enforced: true},
	{Name: "файлы сеансов фреймворка", Kind: File, Class: Unused, Growth: ByCode,
		Limit: "вход — cookie доверенного устройства, сеансы фреймворка продуктом не используются", Age: "—",
		OnCeiling: "не применимо", Enforced: true},

	{Name: "текстовые системные журналы (rsyslog: syslog, kern.log, auth.log, user.log, mail.log, cron.log)", Kind: Journal, Class: Ordinary, Growth: ByNetwork,
		Limit: "у системы предела нет (ротация раз в сутки без maxsize — диск шлюза заполнялся за сутки); сторож диска панели каждые 10 с: при нехватке места обрезает файлы больше 64 МБ до хвоста 4 МБ, в режиме «ограничить» — любой файл больше 256 МБ", Age: "по ротации системы",
		OnCeiling: "обрезка через агента с сохранением хвоста, копии удаляются, rsyslog переоткрывает файл; на каждом такте, пока условие держится; в журнале безопасности — событие в начале серии обрезок и сводное в конце", Enforced: true},
	{Name: "журнал процессов панели и агента", Kind: Journal, Class: Ordinary, Growth: ByNetwork,
		Limit: "общий потолок journald; 1000 сообщений за 30 с на панель и 2000 на агента; повторы сводятся (10 за 5 с)", Age: "по потолку journald",
		OnCeiling: "journald удаляет старые архивы; сверх предела частоты — счётчик отброшенных", Enforced: true},

	{Name: "кэш фреймворка в памяти", Kind: Memory, Class: Unused, Growth: ByCode,
		Limit: "продуктом не используется", Age: "—",
		OnCeiling: "не применимо", Enforced: true},
	{Name: "вёдра ограничителей частоты (internal/ratelimit)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "ведро на адрес; простаивающие полные вёдра удаляются раз в минуту", Age: "минута простоя",
		OnCeiling: "перебор адресов не копит вёдра дольше минуты", Enforced: true},
	{Name: "учёт соединений по адресам (internal/multilisten)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "запись на адрес с открытыми соединениями, не больше 32 соединений на адрес", Age: "пока открыто соединение",
		OnCeiling: "лишнее соединение закрывается сразу; запись удаляется с последним соединением", Enforced: true},
	{Name: "ключи сведения повторов журнала (internal/logdedup)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "не больше 512 строк в учёте", Age: "окно 5 с",
		OnCeiling: "новая строка пишется без учёта", Enforced: true},
	{Name: "окна сведения журнала безопасности (app/services/securitylog)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "не больше 1024 пар «событие + адрес» и по одному ключу переполнения на код события", Age: "окно 60 с",
		OnCeiling: "события сводятся по коду без адреса", Enforced: true},
	{Name: "отметки «последний раз в сети» (app/services/diag)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "не больше 4096 устройств", Age: "до перезапуска панели",
		OnCeiling: "учёт сбрасывается целиком — худший исход одна лишняя запись на устройство", Enforced: true},
	{Name: "очередь калитки перегрузки (internal/admission)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "в работе не больше 8 запросов на ядро, ждущих не больше четырёх ёмкостей; сбрасываемым — половина, петле — своя четверть", Age: "обычный ждёт до 5 с, критичный до 30 с, сбрасываемый не ждёт",
		OnCeiling: "отказ «повторите позже» сразу; критичный отказ называет путь с консоли", Enforced: true},
	{Name: "кольца показателей (internal/metrics)", Kind: Memory, Class: Cache, Growth: ByTime,
		Limit: "на ряд три кольца фиксированной длины: 7200 + 8640×3 + 10080×3 чисел; выделяются один раз при старте, append к истории запрещён тестом", Age: "2 ч / 24 ч / 7 суток по уровням",
		OnCeiling: "новый отсчёт затирает самый старый", Enforced: true},
	{Name: "metrics.bin (история показателей)", Kind: File, Class: Cache, Growth: ByTime,
		Limit: "фиксированный размер: грубые уровни всех рядов, ≈ 4 МБ на проектном составе; тест — размер после суток равен размеру после часа", Age: "перезаписывается раз в 5 минут атомарной заменой",
		OnCeiling: "не растёт по построению; чужой или битый файл отбрасывается по контрольной сумме", Enforced: true},
	{Name: "окна вердикта о потерях путей (app/services/pathmon)", Kind: Memory, Class: Cache, Growth: ByTime,
		Limit: "на путь кольцо из 1000 результатов, путей не больше трёх", Age: "последние 1000 проб (≈ 17 минут)",
		OnCeiling: "новый результат затирает самый старый", Enforced: true},
	{Name: "окно датчиков защиты (app/services/metrics)", Kind: Memory, Class: Cache, Growth: ByTime,
		Limit: "10 отсчётов", Age: "10 с; старше — «данных нет», предохранители закрываются",
		OnCeiling: "новый отсчёт затирает самый старый", Enforced: true},

	{Name: "наборы учёта диагностики в ядре (internal/nftgen, diag_*)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "не больше 4096 адресов в каждом из четырёх наборов", Age: "сутки тишины адреса",
		OnCeiling: "новый адрес не учитывается; трафик не меняется", Enforced: true},
	{Name: "наборы пределов порта панели в ядре (internal/nftgen, panel_*)", Kind: Memory, Class: Cache, Growth: ByNetwork,
		Limit: "не больше 4096 адресов в каждом из двух наборов", Age: "счёт соединений — пока живы соединения адреса; частота — минута тишины",
		OnCeiling: "новый адрес в набор не попадает и его предел не действует; совокупный предел порта от набора не зависит", Enforced: true},

	{Name: "память страницы: полотна графиков (public/js/islands.js)", Kind: Memory, Class: Cache, Growth: ByCode,
		Limit: "выводится на месте: учтённые полотна × ширина × высота × 4 байта × плотность² (плотность не выше 2); полотен после загрузки не прибавляется, неучтённое полотно потолка не имеет", Age: "пока открыта страница",
		OnCeiling: "предохранитель страницы останавливает все острова, освобождает полотна и показывает плашку; значения, отданные сервером, остаются", Debt: "UI-performance-budget"},
}
