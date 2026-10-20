package controllers

import (
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
)

const (
	rearBoardX, rearBoardY = 176, 258
	rjBoardW, rjBoardH     = 42, 34
	rjSlotX                = 296
	rjSlotW, rjSlotH       = 52, 20
	rearSlotStep           = 22
	rjSlotDY               = 8
)

var (
	rearSlotYs  = []int{392, 414, 436, 458, 480, 502, 524}
	rearNICYs   = []int{436, 502}
	rearPrefix  = "pr"
	rearPrefix2 = "pri"
)

func speedText(mbit int) string {
	if mbit >= 1000 {
		g := strconv.FormatFloat(float64(mbit)/1000, 'f', -1, 64)
		return strings.Replace(g, ".", ",", 1) + " Гбит/с"
	}
	return strconv.Itoa(mbit) + " Мбит/с"
}

func placePort(rp ui.RearPort) ui.RearPort {
	if rp.Board {
		rp.X, rp.Y, rp.W, rp.H = rearBoardX, rearBoardY, rjBoardW, rjBoardH
	} else {
		rp.X, rp.W, rp.H = rjSlotX, rjSlotW, rjSlotH
	}
	rp.CY = rp.Y + rp.H/2
	rp.LineX = rp.X + rp.W + 10
	rp.BoxY = rp.CY - 26
	return rp
}

func pcRearOf(f setup.Facts, provider string) (ui.PCRear, map[string]sysinfo.Port) {
	names := make([]string, 0, len(f.Cards))
	for _, c := range f.Cards {
		names = append(names, c.Name)
	}
	ports := map[string]sysinfo.Port{}
	fastest := 0
	for _, p := range sysinfo.Ports(names) {
		ports[p.Name] = p
		if p.SpeedKnown && p.SpeedMbit > fastest {
			fastest = p.SpeedMbit
		}
	}
	slowest := fastest
	for _, p := range ports {
		if p.SpeedKnown && p.SpeedMbit < slowest {
			slowest = p.SpeedMbit
		}
	}
	out := ui.PCRear{Prefix: rearPrefix}
	var guessed []string
	slot := 0
	used := map[int]bool{}

	board := ""
	for _, c := range f.Cards {
		if ports[c.Name].Place == sysinfo.PlaceBoard {
			board = c.Name
			break
		}
	}
	for _, c := range f.Cards {
		if board == "" && ports[c.Name].Place == "" {
			board = c.Name
		}
	}
	if board == "" && len(f.Cards) > 0 {
		board = f.Cards[0].Name
	}
	for _, c := range f.Cards {
		p := ports[c.Name]
		rp := ui.RearPort{Name: c.Name, Link: c.Up, Provider: c.Name == provider}
		if p.SpeedKnown {
			rp.Speed = speedText(p.SpeedMbit)
			if fastest != slowest {
				rp.SpeedLevel = "slow"
				if p.SpeedMbit == fastest {
					rp.SpeedLevel = "fast"
				}
			}
		}
		switch {
		case c.Name == board:
			rp.Board = true
			if p.Place != sysinfo.PlaceBoard {
				guessed = append(guessed, c.Name)
			}
		case slot < len(rearNICYs):
			rp.Y = rearNICYs[slot] + rjSlotDY
			used[rearNICYs[slot]], used[rearNICYs[slot]+rearSlotStep] = true, true
			slot++
			if p.Place != sysinfo.PlaceSlot {
				guessed = append(guessed, c.Name)
			}
		default:
			continue
		}
		rp = placePort(rp)
		if rp.Provider {
			out.Cable = "M10 " + strconv.Itoa(rp.CY+40) + " C 90 " + strconv.Itoa(rp.CY+40) + ", 130 " + strconv.Itoa(rp.CY) + ", " + strconv.Itoa(rp.X-3) + " " + strconv.Itoa(rp.CY)
			out.PlugX, out.PlugY, out.CableLabel = rp.X-22, rp.CY-9, rp.CY+62
		}
		out.Ports = append(out.Ports, rp)
	}

	if board == "" {
		out.Ports = append([]ui.RearPort{placePort(ui.RearPort{Board: true})}, out.Ports...)
	}

	if len(f.Cards) < 2 {
		for _, y := range rearNICYs {
			if !used[y] {
				out.Missing = &ui.RearWant{RingY: y - 3, TextY: y - 7}
				break
			}
		}
	}
	for _, y := range rearSlotYs {
		if !used[y] {
			out.Plain = append(out.Plain, y)
		}
	}
	if len(guessed) > 0 {
		out.Guess = "Место карты " + strings.Join(guessed, ", ") + " на рисунке примерное: система не сообщает, на плате она или в слоте. Главное — куда вставлен кабель."
	}
	return out, ports
}

func portAdvice(provider, office sysinfo.Port) ui.PortAdvice {
	if !provider.SpeedKnown || !office.SpeedKnown {
		return ui.PortAdvice{Single: &ui.WizardNote{Level: ui.None, Title: "Скорость второй карты узнаем, когда вставите кабель офиса",
			Text: "Тогда мастер подскажет, в какое гнездо лучше провайдера, а в какое — офис."}}
	}
	if provider.SpeedMbit == office.SpeedMbit {
		return ui.PortAdvice{Single: &ui.WizardNote{Level: ui.OK, Title: "Подключено правильно",
			Text: "Обе карты одинаково быстрые — провайдера можно вставить в любую."}}
	}
	slow := min(provider.SpeedMbit, office.SpeedMbit)
	under := ui.WizardNote{Key: "under", Label: "до " + speedText(slow)}
	over := ui.WizardNote{Key: "over", Label: "больше " + speedText(slow)}
	if provider.SpeedMbit > office.SpeedMbit {

		under.Level, under.Title = ui.None, "Можно переставить кабели местами — по желанию"
		under.Text = "Карте " + office.Name + " (" + speedText(office.SpeedMbit) + ") хватит на ваш тариф, а быстрая " +
			provider.Name + " (" + speedText(provider.SpeedMbit) + ") пригодится офису — файлы, принтеры, звонки. Переставлять не обязательно: " +
			"если интернет по договору привязан к адресу устройства, после перестановки он может пропасть — мастер это заметит и подскажет, что делать."
		over.Level, over.Title = ui.OK, "Провайдер в быстром гнезде — верно"
		over.Text = "Но офис через " + office.Name + " получит не больше " + speedText(office.SpeedMbit) + ". Если в офисе гоняют большие файлы, поставьте сетевую плату быстрее — она недорогая."
	} else {
		under.Level, under.Title = ui.OK, "Подключено правильно"
		under.Text = "Провайдеру хватает " + speedText(provider.SpeedMbit) + " на ваш тариф, а быстрая карта " + office.Name + " остаётся офису."
		over.Level, over.Title = ui.Warn, "Медленная карта урежет интернет"
		over.Text = "Тариф больше " + speedText(provider.SpeedMbit) + ", а карта " + provider.Name + " быстрее не пропустит. Переставьте провайдера в " +
			office.Name + " (" + speedText(office.SpeedMbit) + ") или замените плату на более быструю."
	}
	return ui.PortAdvice{Options: []ui.WizardNote{under, over}}
}
