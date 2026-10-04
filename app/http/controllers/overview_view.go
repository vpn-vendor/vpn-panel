package controllers

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overload"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overview"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagnose"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

const (
	ownerChannel = "состояние канала от агента"
	ownerGuard   = "запрет выхода мимо канала"
	ownerUpdates = "политика обновлений безопасности"
	ownerCrypto  = "требования шифрования канала"
	ownerPort    = "гигабитный порт — стандарт офисной сети"
)

const overviewFresh = 30 * time.Second

type overviewFacts struct {
	Protected  bool
	Paths      []pathmon.Snapshot
	Protect    metrics.Protect
	Norm       metrics.VoiceNorm
	HasNorm    bool
	Latest     func(row string) (float64, bool)
	Channel    *vpn.Status
	Online     int
	Updates    *updates.Status
	Version    string
	CollectOff bool

	Machine sysinfo.Machine
	Boot    sysinfo.Boot
	BootOK  bool
	Ports   []sysinfo.Port
	Space   diskstat.Space
	SpaceOK bool

	Reliability reliability.Snapshot
}

func gatherOverview() overviewFacts {
	v := vpn.New()
	st := v.Load()
	f := overviewFacts{
		Protected: st.Mode == vpn.ModeBlack && st.ActiveSlug != "",
		Online:    -1,
		Version:   updates.New().InstalledVersion(),
		Latest:    func(string) (float64, bool) { return 0, false },
	}
	if pm := bootstrapPathMonitor(); pm != nil {
		f.Paths = pm.Paths()
	}
	if col := metrics.Current(); col != nil {
		f.Protect = col.Protection()
		switch col.Master().Mode {
		case metrics.Paused, metrics.Off:
			f.CollectOff = true
		}
		f.Latest = func(row string) (float64, bool) {
			now := time.Now()
			pts := col.Query([]string{row}, now.Add(-overviewFresh), now, int(overviewFresh/time.Second)).Rows[row]
			for i := len(pts) - 1; i >= 0; i-- {
				if !math.IsNaN(pts[i].Avg) {
					return pts[i].Avg, true
				}
			}
			return 0, false
		}
	}
	f.Norm, f.HasNorm = metrics.VoiceNormFor(overview.RowsFor(f.Protected).VoiceDelay)
	f.Machine = sysinfo.Read()
	f.Boot, f.BootOK = sysinfo.Uptime()
	if space, err := diskstat.Usage(retention.DataDir()); err == nil {
		f.Space, f.SpaceOK = space, true
	}
	f.Ports = sysinfo.Ports(portNames())
	f.Reliability = reliability.Read(tunnelLiveUp(f))

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if s, err := v.Status(); err == nil {
			f.Channel = s
		}
	}()
	go func() {
		defer wg.Done()
		d := diag.New()
		lans := d.LANs()
		if facts, err := d.Facts(lans); err == nil && facts != nil {
			f.Online = diagnose.OnlineNow(diagnose.Input{LANs: lans, Neighbours: facts.Neighbours})
		}
	}()
	go func() {
		defer wg.Done()
		if s, err := updates.New().Status(); err == nil {
			f.Updates = s
		}
	}()
	wg.Wait()
	return f
}

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
		if f.CollectOff && l.Row != "" {

			l.Level, l.Text, l.Advice = overview.Unknown, l.TextUnknown, l.AdviceUnknown
		}
		lines = append(lines, ui.StatusLine{
			ID: "light-" + strconv.Itoa(i+1), Judged: ui.Judge(ui.Level(l.Level), l.Owner), Text: l.Text, Advice: l.Advice, Row: l.Row,
			Warn: threshold(l.Warn), Bad: threshold(l.Bad), Alive: l.AliveRow,
			TextOK: l.TextOK, TextWarn: l.TextWarn, TextBad: l.TextBad, TextUnknown: l.TextUnknown, TextDown: l.TextDown,
			AdviceOK: l.AdviceOK, AdviceWarn: l.AdviceWarn, AdviceBad: l.AdviceBad, AdviceUnknown: l.AdviceUnknown, AdviceDown: l.AdviceDown,
		})
	}

	val := func(row, unit string) string {
		if v, ok := f.Latest(row); ok && !f.CollectOff {
			return formatUnit(v, unit)
		}
		return ""
	}
	trafficSub := "Весь трафик офиса идёт напрямую через WAN"
	if f.Protected {
		trafficSub = "Весь трафик офиса идёт через VPN"
	}
	voice := ui.ChartCard{
		ID: "chart-voice", Title: "Звонки", Kind: "band", Unit: "ms",
		Sub:  "Сколько разговор ждёт в очереди для звонков; линия — среднее, полоса — от наименьшего до наибольшего",
		Rows: []ui.ChartRow{{Name: rows.VoiceDelay, Label: "задержка", Value: val(rows.VoiceDelay, "ms"), Series: 1}},
	}
	if f.HasNorm {
		voice.Norm = threshold(f.Norm.TargetMs)
		voice.Note = "Зелёная зона — норма, которую держит сама очередь: до " + formatUnit(f.Norm.TargetMs, "ms") + "."
	} else {
		voice.Note = "Очередь для звонков не включена: приоритет разговоров настраивается в разделе QoS."
	}
	bands := []ui.ChartCard{
		{ID: "chart-traffic", Title: "Интернет офиса", Sub: trafficSub, Kind: "band", Unit: "bits",
			Note: "Если полоса упирается в скорость тарифа, офису тесно; звонки при этом спасает очередь QoS — она пропускает их первыми.",
			Rows: []ui.ChartRow{
				{Name: rows.Rx, Label: "входящий", Value: val(rows.Rx, "bits"), Series: 1},
				{Name: rows.Tx, Label: "исходящий", Value: val(rows.Tx, "bits"), Series: 2}}},
		voice,
	}
	spark := func(id, title, row, label, unit, note string, scale *ui.Scale) ui.ChartCard {
		return ui.ChartCard{ID: id, Title: title, Kind: "spark", Unit: unit, Note: note, Scale: scale,
			Rows: []ui.ChartRow{{Name: row, Label: label, Value: val(row, unit), Series: 1}}}
	}

	load := overview.Load(f.Protect, lanCPUMaxBusy, overload.PressureHot)
	sparks := []ui.ChartCard{
		spark("chart-cpu", "Процессор", metrics.RowCPUBusy, "занят", "percent",
			"На нём считается шифрование канала. Постоянно высокая загрузка — повод для сервера мощнее",
			ui.NewScale(load.Warn, load.Bad, load.Owner)),
		spark("chart-mem", "Память", metrics.RowMemUsed, "занято", "percent",
			"Память всей системы; панель берёт из неё немного. Держится у верхнего края — какая-то программа растёт", nil),
		spark("chart-pressure", "Ожидание процессора", metrics.RowPressureCPU, "задачи ждут", "percent",
			"Доля времени, когда задачи ждали процессор. Растёт раньше загрузки — первый признак, что процессора не хватает",
			ui.NewScale(overload.PressureHot, 0, overview.OwnerFuses)),
		{ID: "chart-lan", Title: "Локальная сеть", Kind: "spark", Unit: "bits",
			Note: "Сколько проходит через порт офиса. Упирается в скорость порта — узкое место в кабеле или коммутаторе",
			Rows: []ui.ChartRow{
				{Name: metrics.RowLANRx, Label: "от устройств", Value: val(metrics.RowLANRx, "bits"), Series: 1},
				{Name: metrics.RowLANTx, Label: "к устройствам", Value: val(metrics.RowLANTx, "bits"), Series: 2}}},
		spark("chart-voice-drops", "Потерянные пакеты звонков", rows.VoiceDrops, "сбросов", "rate",
			"Пакеты разговоров, выброшенные очередью: каждый — слышимый обрыв. Появились — смотрите загрузку канала", nil),
	}

	return map[string]any{
		"lights":      ui.StatusGrid{Lines: lines},
		"chips":       ui.WindowChips{},
		"bands":       ui.ChartGrid{Cards: bands, Wide: true},
		"sparks":      ui.ChartGrid{Cards: sparks},
		"tip":         ui.ChartTip{},
		"panel":       ui.ChartPanel{},
		"blocks":      ui.CardGrid{Cards: []ui.LinkCard{channelBlock(f), guardBlock(f), officeBlock(f), updatesBlock(f)}},
		"server":      serverFacts(f),
		"reliability": reliabilityFacts(f),
	}
}

func channelBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "VPN", URL: "/vpn"}
	rtt := func(kind pathmon.Kind) (string, bool) {
		for _, p := range f.Paths {
			if p.Kind == kind && p.State == pathprobe.Up && p.RTT > 0 {
				return formatUnit(float64(p.RTT)/float64(time.Millisecond), "ms"), true
			}
		}
		return "", false
	}
	if !f.Protected {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Режим", Value: "прямой доступ", Note: "VPN выключен: офис выходит в интернет напрямую"})
		if v, ok := rtt(pathmon.Direct); ok {
			b.Metrics = append(b.Metrics, ui.Metric{Label: "Задержка до провайдера", Value: v,
				Note: "Время ответа провайдера; большая — голос идёт с запаздыванием"})
		}
		return b
	}
	if f.Channel == nil {
		b.Note = "Состояние VPN сейчас получить не удалось. Обновите страницу; если повторяется — откройте раздел VPN."
		return b
	}
	state := ui.Metric{Label: "Состояние", Value: "не поднят", Judged: ui.Judge(ui.Bad, ownerChannel),
		Note: "Офис без защищённого канала — звонки и интернет стоят. Причина и что делать — в разделе VPN"}
	if f.Channel.Online {
		state = ui.Metric{Label: "Состояние", Value: "поднят", Judged: ui.Judge(ui.OK, ownerChannel),
			Note: "Канал поднят; с какого времени без обрыва — появится после первой пробы"}
		for _, p := range f.Paths {
			if p.Kind == pathmon.Tunnel && p.State == pathprobe.Up && !p.Since.IsZero() {
				state.Note = "без обрыва " + humanSeconds(int64(time.Since(p.Since).Seconds()))
			}
		}
	}
	b.Metrics = append(b.Metrics, state)
	if f.Channel.Endpoint != "" {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Сервер VPN", Value: f.Channel.Endpoint,
			Note: "Куда подключён канал — адрес из файла подключения"})
	}
	if f.Channel.MTU > 0 {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Размер пакета (MTU)", Value: strconv.Itoa(f.Channel.MTU),
			Note: "Слишком большой рвёт сайты и звонки; подбирается автоматически в разделе VPN"})
	}
	if v, ok := rtt(pathmon.Tunnel); ok {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Задержка до сервера VPN", Value: v,
			Note: "Время ответа сервера VPN; большая — голос идёт с запаздыванием"})
	}
	if v, ok := rtt(pathmon.Beyond); ok {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Задержка за сервером VPN", Value: v,
			Note: "До интернета через канал; сильно больше задержки до сервера — медленно у поставщика VPN"})
	}
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
		b.Metrics = []ui.Metric{{Label: "Запрет выхода мимо VPN", Value: "не стоит", Judged: ui.Judge(ui.Bad, ownerGuard),
			Note: "Трафик офиса может уйти мимо канала. Откройте раздел VPN и примените настройки"}}
	default:
		b.Metrics = []ui.Metric{{Label: "Попыток выйти мимо VPN заблокировано", Value: strconv.FormatInt(f.Channel.BlockedOutbound, 10),
			Judged: ui.Judge(ui.OK, ownerGuard),
			Note:   "С момента последнего применения правил; защита работает, делать ничего не нужно"}}
	}
	return b
}

func officeBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "Офис", URL: "/diagnostics"}
	if f.Online < 0 {
		b.Note = "Число устройств сейчас получить не удалось."
		return b
	}
	b.Metrics = []ui.Metric{{Label: "Устройств в сети сейчас", Value: strconv.Itoa(f.Online), Note: "кто это и готовы ли они к звонкам — в «Диагностике»"}}
	return b
}

func updatesBlock(f overviewFacts) ui.LinkCard {
	b := ui.LinkCard{Title: "Обновления", URL: "/security"}
	if f.Version != "" {
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Установленная версия", Value: "v" + strings.TrimPrefix(f.Version, "v"),
			Note: "Её называют, когда пишут в поддержку"})
	}
	switch {
	case f.Updates == nil:
		b.Note = "Состояние автообновлений сейчас получить не удалось."
	case f.Updates.Enabled:
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Автообновления", Value: "включены", Judged: ui.Judge(ui.OK, ownerUpdates),
			Note: "Исправления безопасности ставятся сами"})
	default:
		b.Metrics = append(b.Metrics, ui.Metric{Label: "Автообновления", Value: "выключены", Judged: ui.Judge(ui.Warn, ownerUpdates),
			Note: "Исправления безопасности придётся ставить вручную; включаются в разделе «Защита»"})
	}
	return b
}

func threshold(v float64) string {
	if v <= 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func formatUnit(v float64, unit string) string {

	num := func(v float64, digits int) string {
		scale := math.Pow(10, float64(digits))
		return strings.Replace(strconv.FormatFloat(math.Round(v*scale)/scale, 'f', digits, 64), ".", ",", 1)
	}
	small := func(v float64) int {
		if v < 10 {
			return 1
		}
		return 0
	}
	switch unit {
	case "bits":
		bits, names, i := v*8, []string{"бит/с", "Кбит/с", "Мбит/с", "Гбит/с"}, 0
		for bits >= 1000 && i < len(names)-1 {
			bits /= 1000
			i++
		}
		digits := 0
		if bits < 10 && i > 0 {
			digits = 1
		}
		return num(bits, digits) + " " + names[i]
	case "ms":
		return num(v, small(v)) + " мс"
	case "percent":
		return num(v, 0) + " %"
	case "rate":
		return num(v, small(v)) + " /с"
	}
	return num(v, small(v))
}

func portNames() []string {
	r := metricsRolesForPage()
	names := make([]string, 0, 4)
	if r.WAN != "" {
		names = append(names, r.WAN)
	}
	names = append(names, r.LANs...)
	return names
}

func serverFacts(f overviewFacts) ui.Facts {
	m := f.Machine
	out := ui.Facts{Title: "Сервер"}

	cpu := ui.Fact{Label: "Процессор", Value: m.CPU.Model,
		Note: "На нём считается шифрование канала; число ядер ядро системы сейчас не сообщило"}
	if m.CPU.Threads > 0 {
		cpu.Note = ui.Plural(m.CPU.Threads, "поток", "потока", "потоков") + " — на них считается шифрование канала"
		if m.CPU.Cores > 0 {
			cpu.Note = ui.Plural(m.CPU.Cores, "ядро", "ядра", "ядер") + ", " + cpu.Note
		}
	}
	out.Items = append(out.Items, cpu)

	crypto := ui.Fact{Label: "Ускорение шифрования", Value: "есть", Judged: ui.Judge(ui.OK, ownerCrypto),
		Note: "Канал шифруется отдельными командами процессора — запас по скорости большой"}
	if !m.CPU.CryptoFast {
		crypto = ui.Fact{Label: "Ускорение шифрования", Value: "нет", Judged: ui.Judge(ui.Warn, ownerCrypto),
			Note: "Шифрование считается обычными командами: скорость канала упрётся в процессор раньше, чем в провайдера"}
	}
	out.Items = append(out.Items, crypto)

	mem := ui.Fact{Label: "Оперативная память", Note: "Объём сообщает ядро системы; сейчас он не прочитан"}
	if m.MemBytes > 0 {
		mem.Value = retention.Human(m.MemBytes)
		mem.Note = "Из неё панель берёт немного; остальное нужно системе и очередям"
	}
	out.Items = append(out.Items, mem)

	disk := ui.Fact{Label: "Накопитель"}
	if len(m.Disks) > 0 {
		d := m.Disks[0]
		parts := []string{}
		if d.Model != "" {
			parts = append(parts, d.Model)
		}
		if d.Kind != "" {
			parts = append(parts, d.Kind)
		}
		if d.Bytes > 0 {
			parts = append(parts, retention.Human(d.Bytes))
		}
		disk.Value = strings.Join(parts, ", ")
	}
	if f.SpaceOK {
		disk.Note = "Свободно " + retention.Human(f.Space.AvailUnpriv) + " — на заполненном диске остановится история и журналы"
	} else {
		disk.Note = "Тип накопителя сообщает сам диск; виртуальный не сообщает ничего"
	}
	out.Items = append(out.Items, disk)

	system := ui.Fact{Label: "Система", Value: m.OSName, Note: "Что установлено на сервере; её называют, когда пишут в поддержку"}
	if m.Kernel != "" {
		system.Note = "Ядро " + m.Kernel
	}
	out.Items = append(out.Items, system)

	work := ui.Fact{Label: "Работает без перезагрузки", Note: "Время работы сообщает ядро системы; сейчас оно не прочитано"}
	if f.BootOK {
		work.Value = humanSeconds(int64(f.Boot.For.Seconds()))
		work.Note = "С " + f.Boot.Since.Local().Format("02.01.2006 15:04") + "; частые перезагрузки — питание, перегрев или сбой системы"
	}
	out.Items = append(out.Items, work)

	for _, p := range f.Ports {
		fact := ui.Fact{Label: "Порт " + p.Name}
		switch {
		case p.SpeedKnown && p.SpeedMbit < 1000:
			fact.Value = strconv.Itoa(p.SpeedMbit) + " Мбит/с"
			fact.Judged = ui.Judge(ui.Warn, ownerPort)
			fact.Note = "Узкое место: быстрее этого офис через порт не получит, замените кабель или коммутатор"
		case p.SpeedKnown:
			fact.Value = strconv.Itoa(p.SpeedMbit) + " Мбит/с"
			fact.Judged = ui.Judge(ui.OK, ownerPort)
			fact.Note = "Скорость порта не ограничивает офис"
		default:
			fact.Note = "Скорость сообщает сама карта; виртуальная её не сообщает"
		}
		if p.Driver != "" && fact.Note != "" {
			fact.Note += " (" + p.Driver + ")"
		}
		out.Items = append(out.Items, fact)
	}
	return out
}
