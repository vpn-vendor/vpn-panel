package controllers

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overview"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/updates"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagnose"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/procstat"
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

	Temp      procstat.Temp
	TempOK    bool
	Mem       procstat.MemInfo
	MemOK     bool
	Uptime    map[string]reliability.Uptime
	Events    []models.AuthEvent
	SpeedDown int
	SpeedUp   int
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
	f.Temp, f.TempOK = procstat.ReadCPUTemp()
	if m, err := procstat.ReadMemInfo(); err == nil {
		f.Mem, f.MemOK = m, true
	}
	kind := overview.RowsFor(f.Protected).Path
	f.Uptime = map[string]reliability.Uptime{}
	for _, w := range uptimeWindows {
		f.Uptime[w.key] = reliability.ReadUptime(kind, w.span, uptimeCells)
	}
	f.Events = recentEvents(feedCap, 0)
	f.SpeedDown, f.SpeedUp = qos.New().MeasuredMbit()

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

func lightLine(id string, l overview.Light, collectOff bool) ui.StatusLine {
	if collectOff && l.Row != "" {

		l.Level, l.Text, l.Advice = overview.Unknown, l.TextUnknown, l.AdviceUnknown
	}
	return ui.StatusLine{
		ID: id, Judged: ui.Judge(ui.Level(l.Level), l.Owner), Text: l.Text, Advice: l.Advice, Row: l.Row,
		Warn: threshold(l.Warn), Bad: threshold(l.Bad), Alive: l.AliveRow,
		TextOK: l.TextOK, TextWarn: l.TextWarn, TextBad: l.TextBad, TextUnknown: l.TextUnknown, TextDown: l.TextDown,
		AdviceOK: l.AdviceOK, AdviceWarn: l.AdviceWarn, AdviceBad: l.AdviceBad, AdviceUnknown: l.AdviceUnknown, AdviceDown: l.AdviceDown,
	}
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
	out := ui.Facts{Title: "Сервер", Tiles: true}

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

func recentEvents(limit int, after uint) []models.AuthEvent {
	var rows []models.AuthEvent
	q := facades.Orm().Query()
	if after > 0 {
		q = q.Where("id > ?", after)
	}
	if err := q.OrderBy("id", "desc").Limit(limit).Find(&rows); err != nil {
		return nil
	}
	return rows
}
