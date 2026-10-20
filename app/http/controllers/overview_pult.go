package controllers

import (
	"strconv"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overload"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overview"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
	"github.com/vpn-vendor/vpn-panel-core/internal/voicescore"
)

const (
	tempWarnShare = 0.8
	tempBadShare  = 0.9
)

const (
	ownerTemp  = "порог перегрева, который сообщает датчик процессора"
	ownerVoice = "модель оценки звонков ITU-T G.107"
)

const uptimeCells = 84

const tileSpan = 600

const feedCap = 7

func overviewView(f overviewFacts) map[string]any {
	rows := overview.RowsFor(f.Protected)
	delay, known := f.Latest(rows.VoiceDelay)
	lights := []overview.Light{
		overview.Internet(f.Protected, f.Paths),
		overview.Voice(f.Protected, f.Norm, f.HasNorm, delay, known),
		overview.Load(f.Protect, lanCPUMaxBusy, overload.PressureHot),
	}
	lines := make([]ui.StatusLine, 0, len(lights))
	for i, l := range lights {
		lines = append(lines, lightLine("light-"+strconv.Itoa(i+1), l, f.CollectOff))
	}
	return map[string]any{
		"pageLive":    true,
		"lights":      ui.StatusGrid{Lines: lines},
		"gauges":      ui.GaugeGrid{Gauges: pultGauges(f)},
		"facts":       pultFacts(f),
		"traffic":     ui.ChartGrid{Cards: []ui.ChartCard{trafficCard(f, rows)}, Wide: true},
		"trio":        ui.PultTrio{Score: scoreCard(f, rows), Uptime: uptimeCard(f), LAN: lanCard(f)},
		"work":        ui.PultWork{Tiles: ui.ChartGrid{Cards: pultTiles(f, rows), Tight: true}, Feed: pultFeed(f.Events)},
		"blocks":      ui.CardGrid{Cards: []ui.LinkCard{channelBlock(f), guardBlock(f), officeBlock(f), updatesBlock(f)}},
		"server":      serverFacts(f),
		"reliability": reliabilityFacts(f),
		"tip":         ui.ChartTip{},
		"panel":       ui.ChartPanel{},
	}
}

func latestOf(f overviewFacts, row string) (float64, bool) {
	if f.CollectOff {
		return 0, false
	}
	return f.Latest(row)
}

func shownOf(f overviewFacts, row, unit string) string {
	if v, ok := latestOf(f, row); ok {
		return formatUnit(v, unit)
	}
	return "—"
}

func pultGauges(f overviewFacts) []ui.Gauge {
	m := f.Machine
	load := overview.Load(f.Protect, lanCPUMaxBusy, overload.PressureHot)
	cpu := ui.Gauge{ID: "gauge-cpu", Title: "Процессор", Tone: ui.ToneCPU, Row: metrics.RowCPUBusy, Unit: "percent", Max: 100,
		Empty: "Сбор показателей выключен или ещё не дал данных"}
	cpu.Value, cpu.Known = latestOf(f, metrics.RowCPUBusy)
	cpu.Note = strings.TrimSpace(m.CPU.Model)
	if m.CPU.Cores > 0 {
		cpu.Note = joinDot(cpu.Note, ui.Plural(m.CPU.Cores, "ядро", "ядра", "ядер"))
	}
	crypto := "ускорение шифрования есть"
	if !m.CPU.CryptoFast {
		crypto = "ускорения шифрования нет"
	}
	cpu.Legend = []ui.GaugeLegend{{Label: crypto, Tone: ui.ToneCPU}}
	cpu = cpu.WithScale(load.Warn, load.Bad, load.Owner)

	mem := ui.Gauge{ID: "gauge-mem", Title: "Оперативная память", Tone: ui.ToneMem, Row: metrics.RowMemUsed, Row2: metrics.RowMemCache,
		Unit: "percent", Max: 100, Empty: "Сбор показателей выключен или ещё не дал данных"}
	mem.Value, mem.Known = latestOf(f, metrics.RowMemUsed)
	mem.Value2, _ = latestOf(f, metrics.RowMemCache)
	if m.MemBytes > 0 {
		mem.Note = retention.Human(m.MemBytes)
	}
	swap := ui.GaugeLegend{Label: "swap не настроен", Tone: ui.ToneMem}
	if f.MemOK && f.Mem.SwapTotal > 0 {
		swap = ui.GaugeLegend{Label: "swap из " + retention.Human(f.Mem.SwapTotal*1024), Row: metrics.RowMemSwap,
			Value: shownOf(f, metrics.RowMemSwap, "percent"), Tone: ui.ToneMem}
	}
	mem.Legend = []ui.GaugeLegend{
		{Label: "программы", Row: metrics.RowMemUsed, Value: shownOf(f, metrics.RowMemUsed, "percent"), Tone: ui.ToneMem},
		{Label: "кэш", Row: metrics.RowMemCache, Value: shownOf(f, metrics.RowMemCache, "percent"), Tone: ui.ToneMem, Faint: true},
		swap,
	}

	disk := ui.Gauge{ID: "gauge-disk", Title: "Диск", Tone: ui.ToneDisk, Row: metrics.RowDiskUsed, Unit: "percent", Max: 100,
		Empty: "Сбор показателей выключен или ещё не дал данных"}
	disk.Value, disk.Known = latestOf(f, metrics.RowDiskUsed)
	if len(m.Disks) > 0 {
		d := m.Disks[0]
		disk.Note = joinDot(d.Kind, humanBytesIf(d.Bytes))
	}
	if f.SpaceOK {
		disk.Note = joinDot(disk.Note, "свободно "+retention.Human(f.Space.AvailUnpriv))
	}
	disk.Legend = []ui.GaugeLegend{{Label: "нагрузка", Row: metrics.RowDiskBusy, Value: shownOf(f, metrics.RowDiskBusy, "percent"), Tone: ui.ToneDisk}}

	temp := ui.Gauge{ID: "gauge-temp", Title: "Температура", Tone: ui.ToneCPU, Row: metrics.RowCPUTemp, Unit: "celsius",
		Empty: "Датчика процессора у этого сервера нет: так бывает у виртуальных машин и старого железа"}
	temp.Value, temp.Known = latestOf(f, metrics.RowCPUTemp)
	if !temp.Known && f.TempOK && !f.CollectOff {
		temp.Value, temp.Known = f.Temp.Cur, true
	}
	if f.TempOK && f.Temp.Crit > 0 {
		temp.Max = f.Temp.Crit
		temp.Note = "Перегрев по датчику — " + strconv.Itoa(int(f.Temp.Crit)) + " °C"
		temp = temp.WithScale(f.Temp.Crit*tempWarnShare, f.Temp.Crit*tempBadShare, ownerTemp)
	} else if temp.Known {
		temp.Note = "Порог перегрева датчик не сообщает"
	}
	if !f.TempOK {
		temp.Row = ""
	}
	return []ui.Gauge{cpu, mem, disk, temp}
}

func joinDot(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " · " + b
}

func humanBytesIf(n uint64) string {
	if n == 0 {
		return ""
	}
	return retention.Human(n)
}

func pultFacts(f overviewFacts) ui.FactStrip {
	var out ui.FactStrip
	work := ui.StripFact{Label: "Работает без перезагрузки", Value: "—"}
	if f.BootOK {
		work.Value = humanSeconds(int64(f.Boot.For.Seconds()))
	}
	online := ui.StripFact{Label: "Устройств в сети", Value: "—"}
	if f.Online >= 0 {
		online.Value = strconv.Itoa(f.Online)
	}
	vpnFact := ui.StripFact{Label: "VPN", Value: "прямой доступ"}
	switch {
	case !f.Protected:
	case f.Channel == nil:
		vpnFact.Value = "нет ответа"
	case f.Channel.Online:
		vpnFact.Value, vpnFact.Judged = "канал поднят", ui.Judge(ui.OK, ownerChannel)
	default:
		vpnFact.Value, vpnFact.Judged = "канал не поднят", ui.Judge(ui.Bad, ownerChannel)
	}
	speed := ui.StripFact{Label: "Последний замер скорости", Value: "не проводился"}
	if f.SpeedDown > 0 || f.SpeedUp > 0 {
		speed.Value = strconv.Itoa(f.SpeedDown) + " / " + strconv.Itoa(f.SpeedUp) + " Мбит/с"
	}
	version := ui.StripFact{Label: "Версия панели", Value: "—"}
	if f.Version != "" {
		version.Value = strings.TrimPrefix(f.Version, "v")
	}
	out.Items = []ui.StripFact{work, online, vpnFact, speed, version}
	return out
}

func trafficCard(f overviewFacts, rows overview.Rows) ui.ChartCard {
	sub := "Весь трафик офиса идёт напрямую через WAN. Полоса упирается в тариф — офису тесно, звонки спасает очередь QoS."
	if f.Protected {
		sub = "Весь трафик офиса идёт через VPN. Полоса упирается в тариф — офису тесно, звонки спасает очередь QoS."
	}
	return ui.ChartCard{ID: "chart-traffic", Title: "Интернет офиса", Sub: sub, Kind: "area", Unit: "bits", Follow: true,
		Chips: &ui.WindowChips{},
		Note:  "Наведите на график — панель покажет значение в точке; щелчок разворачивает его на весь экран.",
		Rows: []ui.ChartRow{
			{Name: rows.Rx, Label: "входящий", Value: shownOf(f, rows.Rx, "bits"), Series: 1},
			{Name: rows.Tx, Label: "исходящий", Value: shownOf(f, rows.Tx, "bits"), Series: 2}}}
}

func scoreCard(f overviewFacts, rows overview.Rows) ui.ScoreCard {
	c := ui.ScoreCard{Row: rows.Score, Good: voicescore.Threshold(voicescore.GoodR), Poor: voicescore.Threshold(voicescore.PoorR),
		Note:  "Оценка от 1 до 5 по задержке, джиттеру и потерям до сервера VPN. Оценивается канал, а не сам разговор.",
		Empty: "Оценка появится через несколько минут после подъёма канала: для неё нужны задержка, джиттер и потери."}
	if !f.Protected {
		c.Note = "Оценка от 1 до 5 по задержке, джиттеру и потерям до провайдера. Оценивается канал, а не сам разговор."
	}
	if v, ok := latestOf(f, rows.Score); ok {
		c.Value, c.Known = v, true
		switch {
		case v >= c.Good:
			c.Level = ui.OK
		case v >= c.Poor:
			c.Level = ui.Warn
		default:
			c.Level = ui.Bad
		}
	}
	c.Parts = []ui.ScorePart{
		{Label: "Задержка", Row: rows.PathAlive, Unit: "ms", Value: shownOf(f, rows.PathAlive, "ms")},
		{Label: "Джиттер", Row: rows.Jitter, Unit: "ms", Value: shownOf(f, rows.Jitter, "ms")},
		{Label: "Потери", Row: rows.Loss, Unit: "percent", Value: shownOf(f, rows.Loss, "percent")},
	}
	return c
}

func uptimeCard(f overviewFacts) ui.UptimeCard {
	card := ui.UptimeCard{Note: "Шлюз выключен — провайдер не виноват: эти часы в процент не входят."}
	for _, w := range uptimeWindows {
		u := f.Uptime[w.key]
		win := ui.UptimeWindow{Key: w.key, Label: w.label, For: w.forText, From: w.from, Checked: w.key == "7d"}
		if p, ok := u.Percent(); ok {
			win.Pct = strings.Replace(strconv.FormatFloat(p, 'f', 2, 64), ".", ",", 1) + " %"
		}
		for _, c := range u.Cells {
			win.Cells = append(win.Cells, spanClass(c))
		}
		win.Down = "провайдер не отвечал: " + timesText(u.Outages) + downTotal(u.Down)
		win.Off = "шлюз был выключен: " + timesText(u.Offs) + downTotal(u.Off)
		if known := u.Known(); win.Pct != "" && known < w.span*9/10 {
			win.Partial = "Данные есть за " + humanSeconds(int64(known.Seconds())) + " из окна: панель наблюдает недавно или старые события вытеснены потолком журнала."
		}
		card.Windows = append(card.Windows, win)
	}
	return card
}

type uptimeWindow struct {
	key, label, forText, from string
	span                      time.Duration
}

var uptimeWindows = []uptimeWindow{
	{"24h", "24 часа", "за сутки", "−24 ч", reliability.Day},
	{"7d", "7 дней", "за 7 дней", "−7 дн", reliability.Week},
	{"30d", "30 дней", "за 30 дней", "−30 дн", reliability.Month},
}

func spanClass(s reliability.Span) string {
	switch s {
	case reliability.SpanUp:
		return "up"
	case reliability.SpanDown:
		return "down"
	case reliability.SpanOff:
		return "off"
	}
	return "unknown"
}

func timesText(n int) string {
	if n == 0 {
		return "ни разу"
	}
	return ui.Plural(n, "раз", "раза", "раз")
}

func downTotal(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return ", всего " + humanSeconds(int64(d.Seconds()))
}

func lanCard(f overviewFacts) ui.ChartCard {
	c := ui.ChartCard{ID: "chart-lan", Title: "Локальная сеть", Kind: "area", Unit: "bits", Span: tileSpan,
		Sub:  "Сколько проходит через порт офиса. Упирается в скорость порта — узкое место в кабеле или коммутаторе.",
		Note: "Последние десять минут.",
		Rows: []ui.ChartRow{
			{Name: metrics.RowLANRx, Label: "от устройств", Value: shownOf(f, metrics.RowLANRx, "bits"), Series: 1},
			{Name: metrics.RowLANTx, Label: "к устройствам", Value: shownOf(f, metrics.RowLANTx, "bits"), Series: 2}}}
	for _, p := range f.Ports {
		if p.SpeedKnown && p.Name == firstLAN() {
			level := ui.OK
			if p.SpeedMbit < 1000 {
				level = ui.Warn
			}
			c.Tag = &ui.Tag{Text: "порт " + strconv.Itoa(p.SpeedMbit) + " Мбит/с", Judged: ui.Judge(level, ownerPort)}
		}
	}
	return c
}

func firstLAN() string {
	if ls := metricsRolesForPage().LANs; len(ls) > 0 {
		return ls[0]
	}
	return ""
}

func pultTiles(f overviewFacts, rows overview.Rows) []ui.ChartCard {
	load := overview.Load(f.Protect, lanCPUMaxBusy, overload.PressureHot)
	ten := &ui.Tag{Text: "10 мин"}
	tile := func(id, title, unit, note string, scale *ui.Scale, r ...ui.ChartRow) ui.ChartCard {

		return ui.ChartCard{ID: id, Title: title, Kind: "tile", Unit: unit, Span: tileSpan, Tag: ten, Scale: scale, Note: note, Sub: note, Rows: r}
	}
	return []ui.ChartCard{
		tile("tile-cpu", "Процессор", "percent", "На нём считается шифрование канала. Постоянно высокая загрузка — повод для сервера мощнее",
			ui.NewScale(load.Warn, load.Bad, load.Owner),
			ui.ChartRow{Name: metrics.RowCPUBusy, Label: "занят", Value: shownOf(f, metrics.RowCPUBusy, "percent"), Tone: ui.ToneCPU}),
		tile("tile-mem", "Оперативная память", "percent", "Держится у верхнего края и растёт — какая-то программа забирает память", nil,
			ui.ChartRow{Name: metrics.RowMemUsed, Label: "программы", Value: shownOf(f, metrics.RowMemUsed, "percent"), Tone: ui.ToneMem}),
		tile("tile-wait", "Задачи ждут", "percent", "Доля времени, когда задачи ждали процессор, память или диск. Растёт раньше загрузки — первый признак нехватки", ui.NewScale(overload.PressureHot, 0, overview.OwnerFuses),
			ui.ChartRow{Name: metrics.RowPressureCPU, Label: "процессор", Value: shownOf(f, metrics.RowPressureCPU, "percent"), Tone: ui.ToneCPU},
			ui.ChartRow{Name: metrics.RowPressureMem, Label: "память", Value: shownOf(f, metrics.RowPressureMem, "percent"), Tone: ui.ToneMem},
			ui.ChartRow{Name: metrics.RowPressureIO, Label: "диск", Value: shownOf(f, metrics.RowPressureIO, "percent"), Tone: ui.ToneDisk}),
		tile("tile-io", "Нагрузка диска", "percent", "Сколько времени накопитель занят. Долго у верхнего края — диск не успевает за записью журналов и истории", nil,
			ui.ChartRow{Name: metrics.RowDiskBusy, Label: "занят", Value: shownOf(f, metrics.RowDiskBusy, "percent"), Tone: ui.ToneDisk}),
		tile("tile-drops", "Потерянные пакеты звонков", "rate", "Пакеты разговоров, выброшенные очередью: каждый — слышимый обрыв. Появились — смотрите загрузку канала", nil,
			ui.ChartRow{Name: rows.VoiceDrops, Label: "сбросов", Value: shownOf(f, rows.VoiceDrops, "rate"), Series: 2}),
		voiceTile(f, rows),
	}
}

func voiceTile(f overviewFacts, rows overview.Rows) ui.ChartCard {
	c := ui.ChartCard{ID: "tile-voice", Title: "Очередь звонков", Kind: "tile", Unit: "ms", Span: tileSpan, Tag: &ui.Tag{Text: "10 мин"},
		Rows: []ui.ChartRow{{Name: rows.VoiceDelay, Label: "ждёт", Value: shownOf(f, rows.VoiceDelay, "ms"), Series: 1}}}
	if f.HasNorm {
		c.Norm = threshold(f.Norm.TargetMs)
		c.Note = "Сколько разговор ждёт в очереди. Зелёная зона — норма, которую держит очередь: до " + formatUnit(f.Norm.TargetMs, "ms") + "."
	} else {
		c.Note = "Очередь для звонков не включена: приоритет разговоров настраивается в разделе QoS."
	}
	c.Sub = c.Note
	return c
}

func pultFeed(events []models.AuthEvent) ui.Feed {
	out := ui.Feed{Cap: feedCap}
	for _, e := range events {
		out.Events = append(out.Events, feedEvent(e))
		if e.ID > out.After {
			out.After = e.ID
		}
	}
	return out
}

func feedEvent(e models.AuthEvent) ui.FeedEvent {
	kind, _ := journalKind(e.Event)
	detail := e.Details
	if e.IP != "" {
		detail = joinDot(detail, "адрес "+e.IP)
	}
	return ui.FeedEvent{ID: e.ID, Time: e.OccurredAt.Local().Format("15:04"), Title: eventTitle(e.Event), Detail: detail,
		Level: journalLevel(kind, e.Event).Level()}
}

func channelBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "VPN", URL: "/vpn"}
	if !f.Protected {
		b.Tag = &ui.Tag{Text: "прямой доступ"}
		b.Metrics = []ui.Metric{{Label: "Режим", Value: "прямой доступ", Note: "VPN выключен: офис выходит в интернет напрямую"}}
		return b
	}
	if f.Channel == nil {
		b.Note = "Состояние VPN сейчас получить не удалось. Обновите страницу; если повторяется — откройте раздел VPN."
		return b
	}
	if f.Channel.Online {
		b.Tag = &ui.Tag{Text: "канал поднят", Judged: ui.Judge(ui.OK, ownerChannel)}
	} else {
		b.Tag = &ui.Tag{Text: "канал не поднят", Judged: ui.Judge(ui.Bad, ownerChannel)}
	}
	if f.Channel.Protocol != "" {
		m := protoMark(f.Channel.Protocol)
		if t := transportLabel(f.Channel.Transport); t != "" {
			m.Label += " · " + t
		}
		b.Mark = &m
	}
	name := f.Channel.Slug
	if name == "" {
		name = "—"
	}
	state := ui.Metric{Label: "Подключение", Value: name, Note: "Офис без защищённого канала — звонки и интернет стоят. Причина и что делать — в разделе VPN"}
	if f.Channel.Online {
		state.Note = "с какого времени без обрыва — появится после первой пробы"
		for _, p := range f.Paths {
			if p.Kind == pathmon.Tunnel && !p.Since.IsZero() && p.State == pathprobe.Up {
				state.Note = "без обрыва " + humanSeconds(int64(time.Since(p.Since).Seconds()))
			}
		}
	}

	if f.Channel.Endpoint != "" {
		state.Note = joinDot(state.Note, "сервер "+f.Channel.Endpoint)
	}
	if f.Channel.MTU > 0 {
		state.Note = joinDot(state.Note, "MTU "+strconv.Itoa(f.Channel.MTU))
	}
	for _, p := range f.Paths {
		if p.Kind == pathmon.Tunnel && p.State == pathprobe.Up && p.RTT > 0 {
			state.Note = joinDot(state.Note, "ответ сервера "+formatUnit(float64(p.RTT)/float64(time.Millisecond), "ms"))
		}
	}
	b.Metrics = []ui.Metric{state}
	return b
}

func guardBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "Защита", URL: "/security"}
	switch {
	case !f.Protected:
		b.Note = "Запрет выхода мимо VPN действует в защищённом режиме; сейчас офис работает напрямую."
	case f.Channel == nil:
		b.Note = "Счётчик защиты сейчас получить не удалось."
	case !f.Channel.OutboundGuard:
		b.Tag = &ui.Tag{Text: "не стоит", Judged: ui.Judge(ui.Bad, ownerGuard)}
		b.Metrics = []ui.Metric{{Label: "Запрет выхода мимо VPN", Value: "не стоит", Judged: ui.Judge(ui.Bad, ownerGuard),
			Note: "Трафик офиса может уйти мимо канала. Откройте раздел VPN и примените настройки"}}
	default:
		b.Tag = &ui.Tag{Text: "действует", Judged: ui.Judge(ui.OK, ownerGuard)}
		b.Metrics = []ui.Metric{{Label: "Попыток выйти мимо VPN заблокировано", Value: strconv.FormatInt(f.Channel.BlockedOutbound, 10),
			Note: "С момента последнего применения правил; защита работает, делать ничего не нужно"}}
	}
	b.Stub = "Счётчик попыток подключиться к шлюзу снаружи"
	return b
}

func officeBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "Офис", URL: "/diagnostics"}
	if f.Online < 0 {
		b.Note = "Число устройств сейчас получить не удалось."
		return b
	}
	b.Tag = &ui.Tag{Text: ui.Plural(f.Online, "в сети", "в сети", "в сети")}
	b.Metrics = []ui.Metric{{Label: "Устройств в сети сейчас", Value: strconv.Itoa(f.Online), Note: "кто это и готовы ли они к звонкам — в «Диагностике»"}}
	return b
}

func updatesBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "Обновления", URL: "/security"}
	switch {
	case f.Updates == nil:
		b.Note = "Состояние автообновлений сейчас получить не удалось."
	case f.Updates.Enabled:
		b.Tag = &ui.Tag{Text: "включены", Judged: ui.Judge(ui.OK, ownerUpdates)}
		b.Metrics = []ui.Metric{{Label: "Исправления безопасности", Value: "ставятся сами", Judged: ui.Judge(ui.OK, ownerUpdates),
			Note: versionNote(f.Version)}}
	default:
		b.Tag = &ui.Tag{Text: "выключены", Judged: ui.Judge(ui.Warn, ownerUpdates)}
		b.Metrics = []ui.Metric{{Label: "Исправления безопасности", Value: "ставятся вручную", Judged: ui.Judge(ui.Warn, ownerUpdates),
			Note: "Автообновления включаются в разделе «Защита»"}}
	}
	return b
}

func versionNote(v string) string {
	if v == "" {
		return ""
	}
	return "Установлена версия " + strings.TrimPrefix(v, "v") + "; её называют, когда пишут в поддержку"
}
