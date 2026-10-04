package overview

import (
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndiag"
)

type Level string

const (
	Unknown Level = ""
	OK      Level = "ok"
	Warn    Level = "warn"
	Bad     Level = "error"
)

type Light struct {
	Level Level
	Text  string

	Row       string
	Warn, Bad float64

	AliveRow                                         string
	TextOK, TextWarn, TextBad, TextUnknown, TextDown string

	Advice                                                     string
	AdviceOK, AdviceWarn, AdviceBad, AdviceUnknown, AdviceDown string

	Owner string
}

func (l Light) at(level Level) Light {
	l.Level = level
	switch level {
	case OK:
		l.Text, l.Advice = l.TextOK, l.AdviceOK
	case Warn:
		l.Text, l.Advice = l.TextWarn, l.AdviceWarn
	case Bad:
		l.Text, l.Advice = l.TextBad, l.AdviceBad
	default:
		l.Text, l.Advice = l.TextUnknown, l.AdviceUnknown
	}
	return l
}

const (
	OwnerDiagnoses = "каталог диагнозов канала"
	OwnerQueue     = "очередь для звонков"
	OwnerFuses     = "предохранители проверки скорости"
)

func grade(v, warn, bad float64) Level {
	switch {
	case v >= bad:
		return Bad
	case v >= warn:
		return Warn
	}
	return OK
}

type Rows struct {
	Rx, Tx     string
	VoiceDelay string
	VoiceDrops string
	Loss       string
	PathAlive  string
}

func RowsFor(protected bool) Rows {
	if protected {
		return Rows{Rx: metrics.RowTunnelRx, Tx: metrics.RowTunnelTx,
			VoiceDelay: metrics.RowTunnelVoiceDelay, VoiceDrops: metrics.RowTunnelVoiceDrops,
			Loss: pathmon.RowTunnelLoss, PathAlive: pathmon.RowTunnelRTT}
	}
	return Rows{Rx: metrics.RowWANRx, Tx: metrics.RowWANTx,
		VoiceDelay: metrics.RowWANVoiceDelay, VoiceDrops: metrics.RowWANVoiceDrops,
		Loss: pathmon.RowDirectLoss, PathAlive: pathmon.RowDirectRTT}
}

func Internet(protected bool, paths []pathmon.Snapshot) Light {
	rows := RowsFor(protected)
	l := Light{
		Row: rows.Loss, AliveRow: rows.PathAlive, Warn: vpndiag.VoiceLossLimitPct, Bad: vpndiag.WebOnlyLossPct,
		TextOK: "Интернет работает", TextWarn: "Интернет работает с потерями",
		TextBad: "Интернет теряет слишком много — звонкам плохо", TextUnknown: "Состояние интернета не измеряется",
		TextDown: "Интернет не отвечает",
		Owner:    OwnerDiagnoses,
		AdviceOK: "Потери пакетов не мешают звонкам. Делать ничего не нужно",
		AdviceWarn: "Потери выше нормы для звонков — разговор может прерываться. Если держится дольше нескольких минут, " +
			"откройте «Диагностику» и проверьте канал",
		AdviceBad: "Потерь столько, что звонки рвутся, работают только сайты. Проверьте кабель провайдера; " +
			"если повторяется — звоните провайдеру",
		AdviceUnknown: "Проба пути выключена или ещё не дала ответа. Сбор показателей включается в разделе «Защита»",
		AdviceDown:    "Провайдер не отвечает. Проверьте кабель WAN и оборудование провайдера",
	}
	if protected {
		l.TextOK = "Интернет работает, офис выходит через VPN"
		l.TextDown = "VPN не отвечает — офис без интернета"
		l.AdviceBad = "Потерь столько, что звонки рвутся, работают только сайты. Откройте раздел VPN: " +
			"проверка канала покажет, у кого потери — у провайдера или у сервера VPN"
		l.AdviceDown = "Сервер VPN не отвечает. Откройте раздел VPN: там причина и кнопка проверки канала"
	}
	level, seen := Unknown, false
	for _, p := range paths {
		if protected == (p.Kind == pathmon.Direct) {
			continue
		}
		switch p.State {
		case pathprobe.Down:
			down := l.at(Bad)
			down.Text, down.Advice = l.TextDown, l.AdviceDown
			return down
		case pathprobe.Up:
			seen = true
			if p.LossKnown {
				if g := grade(p.LossPct, l.Warn, l.Bad); worse(g, level) {
					level = g
				}
			} else if level == Unknown {
				level = OK
			}
		}
	}
	if !seen {
		return l.at(Unknown)
	}
	return l.at(level)
}

func worse(a, b Level) bool {
	rank := map[Level]int{Unknown: 0, OK: 1, Warn: 2, Bad: 3}
	return rank[a] > rank[b]
}

func Voice(protected bool, norm metrics.VoiceNorm, hasNorm bool, delayMs float64, known bool) Light {
	l := Light{
		TextOK: "Звонки в норме", TextWarn: "Звонки ждут в очереди дольше нормы",
		TextBad: "Очередь для звонков не справляется", TextUnknown: "Звонки: нет данных",
		Owner:      OwnerQueue,
		AdviceOK:   "Разговоры проходят очередь без задержки. Делать ничего не нужно",
		AdviceWarn: "Очередь держит разговоры дольше своей цели — канал загружен. Посмотрите график «Интернет офиса»: кто занимает канал",
		AdviceBad: "Очередь не успевает — голос будет с задержками и обрывами. Уменьшите загрузку канала " +
			"или проверьте скорость, заданную в разделе QoS",
		AdviceUnknown: "Очередь ещё не дала данных или сбор показателей выключен в разделе «Защита»",
	}
	if !hasNorm {
		l.TextUnknown = "Очередь для звонков не включена — приоритет разговоров настраивается в разделе QoS"
		l.AdviceUnknown = "Без очереди звонки делят канал с загрузками файлов и рвутся первыми. Включите QoS"
		return l.at(Unknown)
	}
	l.Row, l.Warn, l.Bad = RowsFor(protected).VoiceDelay, norm.TargetMs, norm.IntervalMs
	if !known {
		return l.at(Unknown)
	}
	return l.at(grade(delayMs, l.Warn, l.Bad))
}

func Load(p metrics.Protect, busyLimit, pressureHot float64) Light {
	l := Light{
		Row: metrics.RowCPUBusy, Warn: busyLimit, Bad: (busyLimit + 100) / 2,
		TextOK: "Сервер не перегружен", TextWarn: "Сервер загружен", TextBad: "Сервер перегружен",
		TextUnknown: "Нагрузка сервера: нет данных",
		Owner:       OwnerFuses,
		AdviceOK:    "Процессору хватает запаса на шифрование канала. Делать ничего не нужно",
		AdviceWarn:  "Процессор занят настолько, что панель откладывает тяжёлые проверки. Если держится — посмотрите график «Процессор»",
		AdviceBad: "Шифрованию канала не хватает процессора — звонки могут страдать. Выясните, что грузит сервер; " +
			"при постоянной нагрузке офису нужен сервер мощнее",
		AdviceUnknown: "Сбор показателей выключен или ещё не набрал данных",
	}
	if !p.OK {
		return l.at(Unknown)
	}
	level := grade(p.CPUBusy, l.Warn, l.Bad)
	if p.PressureCPU >= pressureHot && worse(Warn, level) {
		level = Warn
	}
	return l.at(level)
}
