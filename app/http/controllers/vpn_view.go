package controllers

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	vpnsvc "github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const vpnJudgeOwner = "раздел VPN"

const tunnelWord = "VPN"

func tunnelModeName() string { return "Весь офис через " + tunnelWord }

func vpnTag(text string, level ui.Level) ui.Tag {
	return ui.Tag{Text: text, Judged: ui.Judge(level, vpnJudgeOwner)}
}

func protoMark(id string) ui.ProtoMark {
	for i, d := range vpnproto.All() {
		if d.ID == vpnproto.Stored(id) {
			return ui.ProtoMark{Mono: monogram(d.Label), Label: d.Label, Tone: i + 1}
		}
	}
	return ui.ProtoMark{Mono: "VPN", Label: id}
}

func monogram(label string) string {
	var out []rune
	for _, r := range label {
		if unicode.IsUpper(r) && len(out) < 2 {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		rs := []rune(strings.ToUpper(label))
		if len(rs) > 2 {
			rs = rs[:2]
		}
		out = rs
	}
	return string(out)
}

func vpnUploadZone(csrf string, hasProfiles bool) *ui.UploadZone {
	z := &ui.UploadZone{
		ID: "vpn-upload-file", Action: "/vpn/import", CSRF: csrf, FileName: "config",
		Accept: uploadView()["Accept"].(string),
		Title:  "Перетащите файл сюда или выберите на компьютере",
		Text:   "Файл подключения от поставщика VPN",
		NameField: ui.Field{ID: "vpn-upload-name", Name: "name", Label: "Название подключения",
			Placeholder: "например, Основное", MaxLength: 60, Autocomplete: "off",
			Hint: "Пусто — возьмём имя файла."},
		Button: ui.Button{Label: "Загрузить", Icon: "upload"},
	}
	if hasProfiles {
		z.Title = "Добавить подключение"
		z.Text = "Перетащите файл от поставщика сюда или выберите на компьютере."
	}
	for _, d := range vpnproto.All() {
		z.Kinds = append(z.Kinds, ui.UploadKind{Mark: protoMark(string(d.ID)), Ext: d.FileExts[0]})
	}
	return z
}

type vpnLink struct {
	Known     bool
	Black     bool
	Online    bool
	Handshake int64
}

func vpnProfileGrid(rows []profileView, link vpnLink, savedBlack bool, added, csrf string) ui.ProfileGrid {

	g := ui.ProfileGrid{Upload: vpnUploadZone(csrf, len(rows) > 0)}

	anyActive := false
	for _, r := range rows {
		anyActive = anyActive || r.Active
	}
	for i, r := range rows {
		c := ui.ProfileCard{
			Form: "vpn-apply", Name: "profile", Value: r.Slug, Checked: r.Active || (!anyActive && i == 0),
			Title: r.Name, Mark: r.Mark, Protocol: r.Protocol + " по " + r.Transport,
			PickLabel: "Переключиться на это", Fresh: added != "" && r.Slug == added,
		}
		if c.Checked && !r.Active {
			c.PickLabel = "Выбрано"
		}
		c.State = vpnTag("наготове", ui.None)
		if r.Active {
			c.PickLabel = "Текущее подключение"
			switch {
			case !link.Known:
				c.State = vpnTag("выбрано", ui.None)
			case !link.Black:
				c.State = vpnTag("выбрано, канал выключен", ui.None)
			case link.Online:
				c.State = vpnTag("работает", ui.OK)
				c.Current = true
				c.Live = "Канал поднят · обмен с сервером " + humanSeconds(link.Handshake) + " назад"
			default:
				c.State = vpnTag("не отвечает", ui.Bad)
			}
		}
		if r.Endpoint != "" {
			c.Facts = append(c.Facts, ui.ProfileFact{Label: "Сервер", Value: r.Endpoint, CopyID: "pf-" + r.Slug + "-server"})
		}
		if r.Addresses != "" {
			fact := ui.ProfileFact{Label: "Адрес в канале", Value: r.Addresses}
			if r.Addresses != "назначает сервер" {
				fact.CopyID = "pf-" + r.Slug + "-addr"
			}
			c.Facts = append(c.Facts, fact)
		}
		if r.FullTunnel {
			c.Tags = append(c.Tags, vpnTag("весь трафик", ui.OK))
		} else {
			c.Tags = append(c.Tags, vpnTag("не весь трафик", ui.Warn))
		}
		switch {
		case r.VoiceFit:
			c.Tags = append(c.Tags, vpnTag("годится для разговоров", ui.OK))
		case r.Transport == transportLabel(vpndriver.TransportTCP):
			c.Tags = append(c.Tags, vpnTag("TCP: для разговоров не годится", ui.Warn))
		default:
			c.Tags = append(c.Tags, vpnTag("для разговоров не годится", ui.Warn))
		}
		if c.Fresh {
			c.Tags = append([]ui.Tag{vpnTag("только что загружено", ui.OK)}, c.Tags...)
		}
		switch {
		case r.Active && savedBlack:
			c.DeleteNote = "Удалить нельзя, пока через него идёт весь офис: сначала включите прямой доступ."
		case r.Active:
			c.Delete = &ui.ActionForm{Action: "/vpn/remove", CSRF: csrf,
				Hidden:   map[string]string{"profile": r.Slug},
				Button:   ui.Button{Label: "Удалить", Kind: "danger-outline", Small: true},
				Question: "Удалить выбранное подключение «" + r.Name + "» вместе с его ключом? Чтобы снова включить " + tunnelWord + ", понадобится загрузить файл заново."}
		default:
			c.Delete = &ui.ActionForm{Action: "/vpn/remove", CSRF: csrf,
				Hidden:   map[string]string{"profile": r.Slug},
				Button:   ui.Button{Label: "Удалить", Kind: "danger-outline", Small: true},
				Question: "Удалить подключение «" + r.Name + "» вместе с его ключом?"}
		}
		g.Cards = append(g.Cards, c)
	}
	return g
}

func vpnModeCards(black, hasProfiles bool) ui.ChoiceCards {
	tunnel := ui.ChoiceCardOption{Value: vpnsvc.ModeBlack, Label: tunnelModeName(), Checked: black && hasProfiles, Tone: "safe", Icon: "lock",
		Tags: []ui.Tag{vpnTag("рекомендуем · безопасно", ui.OK)},
		Points: []ui.Point{
			{Kind: "plus", Text: "Провайдер не видит, какие сайты открывают сотрудники"},
			{Kind: "plus", Text: "Сайты видят адрес сервера " + tunnelWord + ", а не офиса"},
			{Kind: "plus", Text: "Звонки внутри канала идут первыми, как и без него"},
			{Kind: "note", Text: "Скорость ограничена сервером поставщика"},
		}}
	if !hasProfiles {
		tunnel.Disabled = true
		tunnel.Tags = append(tunnel.Tags, vpnTag("сначала загрузите файл подключения", ui.Warn))
	}
	return ui.ChoiceCards{Name: "mode", Legend: "Как офис выходит в интернет", Options: []ui.ChoiceCardOption{
		tunnel,
		{Value: vpnsvc.ModeWhite, Label: "Прямой доступ в интернет", Checked: !black || !hasProfiles, Tone: "risk", Icon: "eye",
			Tags: []ui.Tag{vpnTag("без защиты канала", ui.Warn)},
			Points: []ui.Point{
				{Kind: "plus", Text: "Полная скорость провайдера"},
				{Kind: "minus", Text: "Провайдер видит адреса всех сайтов"},
				{Kind: "minus", Text: "Сайты видят настоящий адрес офиса"},
				{Kind: "note", Text: "Приоритет звонков и защита шлюза работают"},
			}},
	}}
}

func vpnFailCards(strict bool) ui.ChoiceCards {
	return ui.ChoiceCards{Name: "on_failure", Legend: "Если канал пропадёт", Options: []ui.ChoiceCardOption{
		{Value: vpnsvc.FailStrict, Label: "Блокировать интернет в офисе", Checked: strict, Tone: "safe", Icon: "shield",
			Tags: []ui.Tag{vpnTag("рекомендуем · без утечек", ui.OK)},
			Points: []ui.Point{
				{Kind: "plus", Text: "Ни один пакет не уйдёт мимо канала"},
				{Kind: "plus", Text: "Панель сама переподключается и возвращает интернет"},
				{Kind: "minus", Text: "Пока канала нет, в офисе нет интернета"},
			}},
		{Value: vpnsvc.FailDirect, Label: "Выпускать напрямую с предупреждением", Checked: !strict, Tone: "risk", Icon: "warning",
			Tags: []ui.Tag{vpnTag("трафик виден при обрыве", ui.Warn)},
			Points: []ui.Point{
				{Kind: "plus", Text: "Офис работает без перерыва"},
				{Kind: "minus", Text: "Во время обрыва провайдер видит трафик офиса"},
				{Kind: "note", Text: "Панель громко предупредит и вернёт защиту сама"},
			}},
	}}
}

func vpnDNSCards(useConfig bool, configDNS string) ui.ChoiceCards {
	hint := "Запросы имён уйдут на сервер, указанный в файле подключения. За его политику панель ручаться не может."
	if configDNS != "" {
		hint = "Файл выбранного подключения просит сервер имён " + configDNS + ". За его политику панель ручаться не может."
	}
	return ui.ChoiceCards{Name: "dns_choice", Legend: "Серверы имён", Form: "vpn-apply", Options: []ui.ChoiceCardOption{
		{Value: vpnsvc.DNSOurs, Label: "Резолвер офиса через " + tunnelWord, Checked: !useConfig, Tone: "safe",
			Hint: "Имена разрешает резолвер шлюза, и в защищённом режиме его запросы уходят только внутрь канала.",
			Tags: []ui.Tag{vpnTag("рекомендуем", ui.OK)}},
		{Value: vpnsvc.DNSConfig, Label: "Сервер имён из файла подключения", Checked: useConfig, Hint: hint},
	}}
}

type vpnScene struct {
	Kind    string
	Hero    ui.HeroStatus
	Path    ui.TrafficPath
	Metrics ui.MetricGrid
}

type vpnFacts struct {
	Status    *vpnsvc.Status
	Black     bool
	Strict    bool
	Active    *profileView
	Protocol  string
	Transport string
	RxText    string
	TxText    string
	Unknown   string

	NeverEnabled bool
}

func serverSub(a *profileView, tail string) string {
	if a == nil {
		return tail
	}
	if tail == "" {
		return a.Name
	}
	return a.Name + " " + tail
}

func directPath(a *profileView, ready bool, aria string) ui.TrafficPath {
	p := ui.TrafficPath{Aria: aria,
		Gateway: ui.PathNode{Sub: "пропускает трафик как есть", Mark: "warn"},
		Link:    "open", LinkTag: vpnTag("напрямую · без шифрования", ui.Warn),
		Provider: "адреса всех сайтов", ProviderWarn: true,
		Server: ui.PathNode{State: "dim", Mark: "warn", Sub: serverSub(a, "наготове")},
		Exit:   "сайты видят настоящий адрес офиса"}
	switch {
	case a == nil:
		p.Server = ui.PathNode{State: "wait", Mark: "add", Sub: "добавьте подключение"}
	case ready:
		p.Gateway.Sub = "ждёт включения " + tunnelWord
		p.Server = ui.PathNode{Mark: "ok", Sub: a.Name + " готов"}
	}
	return p
}

func vpnSceneOf(f vpnFacts) vpnScene {
	a := f.Active
	if a == nil {
		return vpnScene{Kind: "empty",
			Hero: ui.HeroStatus{Title: "Офис пока без защиты", Icon: "shield-alert", Judged: ui.Judge(ui.Warn, vpnJudgeOwner),
				Text: "Трафик идёт напрямую через провайдера. Загрузите файл подключения от поставщика " + tunnelWord + " — это займёт минуту.",
				Tags: []ui.Tag{vpnTag(tunnelWord+" не настроен", ui.Warn)}},
			Path: directPath(nil, false, "Трафик офиса идёт напрямую через провайдера, подключения к "+tunnelWord+" нет.")}
	}
	st := f.Status
	if st == nil {
		s := vpnScene{Kind: "unknown", Hero: ui.HeroStatus{Title: "Состояние канала неизвестно", Icon: "shield-alert", Text: f.Unknown}}
		if !f.Black {
			s.Path = directPath(a, f.NeverEnabled, "Выбран прямой доступ; состояние канала неизвестно.")
			return s
		}
		s.Path = ui.TrafficPath{Aria: "Выбран режим «" + tunnelModeName() + "»; состояние неизвестно.",
			Gateway: ui.PathNode{Sub: "ждёт ответа службы"},
			Link:    "unknown", LinkTag: vpnTag("состояние неизвестно", ui.None),
			Provider: "станет известно, когда служба ответит",
			Server:   ui.PathNode{Sub: serverSub(a, "")},
			Exit:     "через сервер " + tunnelWord}
		return s
	}

	server := a.Endpoint
	if st.EndpointIP != "" {
		server = st.EndpointIP
	}
	failTag := vpnTag("при обрыве интернет закрыт", ui.OK)
	if !f.Strict {
		failTag = vpnTag("при обрыве — напрямую", ui.Warn)
	}
	protoTag := vpnTag(f.Protocol+" по "+f.Transport, ui.None)

	if st.Mode != vpnsvc.ModeBlack {
		if f.NeverEnabled {
			return vpnScene{Kind: "direct",
				Hero: ui.HeroStatus{Title: "Файл загружен, осталось включить " + tunnelWord, Icon: "shield-alert",
					Text:   "Подключение «" + a.Name + "» на месте и проверено. Один шаг — и весь офис пойдёт через " + tunnelWord + ".",
					Judged: ui.Judge(ui.Warn, vpnJudgeOwner),
					Tags:   []ui.Tag{vpnTag(tunnelWord+" выключен", ui.Warn), vpnTag("подключение готово", ui.OK)}},
				Path: directPath(a, true, "Подключение загружено, трафик офиса пока идёт напрямую.")}
		}
		return vpnScene{Kind: "direct",
			Hero: ui.HeroStatus{Title: "Офис выходит в интернет напрямую", Icon: "shield-alert",
				Text:   tunnelWord + " выключен: провайдер видит, какие сайты открывают сотрудники, а сайты видят настоящий адрес офиса. Подключение «" + a.Name + "» загружено и включится за несколько секунд.",
				Judged: ui.Judge(ui.Warn, vpnJudgeOwner), Tags: []ui.Tag{vpnTag(tunnelWord+" выключен", ui.Warn)}},
			Path: directPath(a, false, "Трафик офиса идёт напрямую через провайдера, сервер "+tunnelWord+" не используется.")}
	}

	s := vpnScene{Kind: "up", Path: ui.TrafficPath{
		Gateway: ui.PathNode{Mark: "ok", Sub: "шифрует трафик офиса"},
		Link:    "ok", LinkTag: vpnTag("зашифровано · "+f.Protocol, ui.OK),
		Provider: "только факт подключения",
		Server:   ui.PathNode{Mark: "ok", Sub: a.Name + " · " + server},
		Exit:     "сайты видят адрес сервера " + tunnelWord}}
	switch {
	case st.Online && st.DataPlane.IsYes():
		s.Hero = ui.HeroStatus{Title: "Канал поднят: провайдер не видит, что делает офис", Icon: "shield",
			Text:   "Весь трафик офиса идёт зашифрованным через «" + a.Name + "». Сайты видят адрес сервера " + tunnelWord + ", а не офиса.",
			Judged: ui.Judge(ui.OK, vpnJudgeOwner)}
		s.Path.Aria = "Офис, шлюз, зашифрованный канал через провайдера, сервер " + tunnelWord + ", интернет. Канал поднят."
	case st.Online && !st.DataPlane.Known():
		s.Hero = ui.HeroStatus{Title: "Канал установлен, идёт проверка прохождения данных", Icon: "shield-alert",
			Text: "Через несколько секунд панель скажет, идут ли данные через канал.", Judged: ui.Judge(ui.Warn, vpnJudgeOwner)}
		s.Path.Link, s.Path.LinkTag = "unknown", vpnTag("идёт проверка", ui.None)
		s.Path.Aria = "Канал установлен, проверка прохождения данных идёт."
	case st.Online:
		s.Hero = ui.HeroStatus{Title: "Канал установлен, но данные через него не идут", Icon: "shield-x",
			Text: "Подробности — в разборе ниже.", Judged: ui.Judge(ui.Bad, vpnJudgeOwner)}
		s.Path.Link, s.Path.LinkTag = "broken", vpnTag("данные не идут", ui.Bad)
		s.Path.Server = ui.PathNode{Mark: "error", Sub: a.Name + " отвечает, данные не идут"}
		s.Path.Aria = "Канал установлен, но данные через него не идут."
	case st.Degraded:
		s.Kind = "down"
		s.Hero = ui.HeroStatus{Title: "Канал не отвечает, офис выходит напрямую", Icon: "shield-x",
			Text:   "Так выбрано в настройке «выпускать напрямую»: пока канала нет, трафик офиса виден провайдеру. Панель сама повторяет попытки и вернёт защиту.",
			Judged: ui.Judge(ui.Bad, vpnJudgeOwner)}
		s.Path = ui.TrafficPath{Aria: "Канал оборван, трафик офиса идёт напрямую через провайдера.",
			Gateway: ui.PathNode{Mark: "warn", Sub: "выпускает напрямую"},
			Link:    "open", LinkTag: vpnTag("канал оборван · трафик напрямую", ui.Bad),
			Provider: "трафик офиса", ProviderWarn: true,
			Server: ui.PathNode{Mark: "error", Sub: a.Name + " не отвечает"},
			Exit:   "сайты видят настоящий адрес офиса"}
	default:
		s.Kind = "down"
		s.Hero = ui.HeroStatus{Title: "Канал не отвечает, офис закрыт от интернета", Icon: "shield-x",
			Text:   "Так и задумано: при обрыве ничего не уходит мимо канала. Панель сама повторяет попытки, а переподключиться можно и вручную.",
			Judged: ui.Judge(ui.Bad, vpnJudgeOwner)}
		s.Path = ui.TrafficPath{Aria: "Канал оборван: шлюз закрыл офис от интернета, сервер " + tunnelWord + " не отвечает.",
			Gateway: ui.PathNode{Mark: "error", Sub: "интернет офиса закрыт"},
			Link:    "broken", LinkTag: vpnTag("канал оборван", ui.Bad),
			Provider: "ничего: трафик не уходит",
			Server:   ui.PathNode{Mark: "error", Sub: a.Name + " не отвечает"},
			Exit:     "недоступен до возврата канала"}
	}
	s.Hero.Tags = []ui.Tag{protoTag, failTag}

	m := &s.Metrics.Metrics
	if st.Online {
		*m = append(*m, ui.Metric{Label: "Последний обмен с сервером", Icon: "clock", Hue: "ok",
			Value: humanSeconds(st.HandshakeS), Unit: "назад", Note: "сервер подключения отвечает каналу"})
	} else {
		*m = append(*m, ui.Metric{Label: "Последний обмен с сервером", Icon: "clock", Hue: "error", Value: "—",
			Note: "ответа от сервера подключения нет"})
		if server != "" {
			*m = append(*m, ui.Metric{Label: "Сервер подключения", Icon: "server", Hue: "srv", Value: server,
				Note: "адрес из файла поставщика", CopyID: "vpn-server-addr"})
		}
		switch {
		case st.RetryPaused:
			*m = append(*m, ui.Metric{Label: "Попытки подключения", Icon: "refresh", Hue: "amber", Value: "приостановлены",
				Note: "почему и что делать — в разборе ниже", Judged: ui.Judge(ui.Warn, vpnJudgeOwner)})
		case st.RetryInSec > 0:
			*m = append(*m, ui.Metric{Label: "Следующая попытка", Icon: "refresh", Hue: "amber", Value: "через " + humanSeconds(st.RetryInSec),
				Note: "панель переподключается сама"})
		}
	}
	if st.Present {
		*m = append(*m, ui.Metric{Label: "Передано через канал", Icon: "transfer", Hue: "office", Value: f.RxText,
			Note: "принято; отправлено " + f.TxText})
	}
	if f.Protocol != "" && st.Online {
		note := "шифрование в процессе"
		if st.KernelDataPlane {
			note = "шифрование в ядре, быстро"
		}
		*m = append(*m, ui.Metric{Label: "Протокол", Icon: "lock", Hue: "gw", Value: f.Protocol, Unit: "по " + f.Transport, Note: note})
	}
	if st.Online && st.Cores > 0 {
		cpu := ui.Metric{Label: "Процессор", Icon: "chip", Hue: "amber", Value: ui.Plural(st.Cores, "ядро", "ядра", "ядер"), Note: "шифрует канал"}
		if st.Load1 > 0 {
			cpu.Note = fmt.Sprintf("нагрузка %.2f, шифрует канал", st.Load1)
		}
		*m = append(*m, cpu)
	}
	return s
}

func vpnEnableForm(csrf string, settings vpnsvc.Settings, slug string) *ui.ActionForm {
	mtu := ""
	if settings.MTU > 0 {
		mtu = strconv.Itoa(settings.MTU)
	}
	dns := settings.DNSChoice
	if dns == "" {
		dns = vpnsvc.DNSOurs
	}
	fail := settings.OnFailure
	if fail == "" {
		fail = vpnsvc.FailStrict
	}
	return &ui.ActionForm{Action: "/vpn/apply", CSRF: csrf,
		Hidden: map[string]string{"profile": slug, "mode": vpnsvc.ModeBlack,
			"on_failure": fail, "dns_choice": dns, "mtu": mtu},
		Button:   ui.Button{Label: "Включить " + tunnelWord + " для всего офиса", Icon: "lock"},
		Question: "Весь трафик офиса пойдёт через " + tunnelWord + ". Разговоры прервутся на несколько секунд. Включить?"}
}

func vpnVerdictKind(s vpnsvc.Settings) string {
	switch {
	case s.Mode != vpnsvc.ModeBlack:
		return "open"
	case s.OnFailure == vpnsvc.FailDirect:
		return "partial"
	}
	return "safe"
}

type vpnSetupFacts struct {
	RolesReady  bool
	HasProfiles bool
	Enabled     bool
	Known       bool
	Online      bool
	Checked     bool
	Running     bool
	Slug        string
	Settings    vpnsvc.Settings
}

func vpnSetup(f vpnSetupFacts, csrf string) *ui.Checklist {
	steps := []ui.CheckStep{
		{Title: "Назначьте карты в интернет и в офис",
			Text: "На странице «Сеть» одной карте — роль «Интернет», другой — «Офис». Без этого каналу не через что идти.",
			Link: &ui.PageLink{URL: "/network", Label: "Открыть «Сеть»", Icon: "network"}},
		{Title: "Загрузите файл подключения",
			Text: "Его выдаёт поставщик " + tunnelWord + ": " + protoFilesText() + ".",
			Link: &ui.PageLink{URL: "#vpn-profiles", Label: "К загрузке", Icon: "upload"}},
		{Title: "Включите " + tunnelWord + " для всего офиса",
			Text: "Шлюз поднимет канал, и весь трафик офиса пойдёт через него. Разговоры прервутся на несколько секунд."},
		{Title: "Дождитесь, пока канал поднимется",
			Text: "Обычно это занимает до минуты: состояние видно вверху страницы."},
		{Title: "Проверьте качество канала",
			Text: "Быстрая проверка — около полминуты, разговорам не мешает. Она покажет, годится ли канал для звонков."},
	}
	if f.HasProfiles && f.Slug != "" {
		steps[2].Action = vpnEnableForm(csrf, f.Settings, f.Slug)
	}
	if f.Enabled && f.Known && !f.Online {
		steps[3].Text = "Канал пока не отвечает. Что случилось и что делать — в разборе выше."
	}
	if f.Running {
		steps[4].Text = "Проверка идёт — страница обновится сама."
	} else {
		steps[4].Action = &ui.ActionForm{Action: "/vpn/check", CSRF: csrf, Hidden: map[string]string{"mode": "quick"},
			Button: ui.Button{Label: "Быстрая проверка", Kind: "secondary", Small: true}}
	}
	done := []bool{f.RolesReady, f.HasProfiles, f.Enabled, f.Enabled && f.Known && f.Online, f.Checked}
	return ui.NewChecklist("vpn-setup", "Как включить "+tunnelWord,
		"Пять шагов от пустого шлюза до работающего канала. Сделанные отмечены, текущий — с кнопкой.", steps, done)
}

func protoFilesText() string {
	var parts []string
	for _, d := range vpnproto.All() {
		parts = append(parts, d.FileExts[0]+" для "+d.Label)
	}
	return "файл " + strings.Join(parts, " или ")
}

func vpnReconnectView(st *vpnsvc.Status, wait time.Duration, csrf string) (*ui.ActionForm, string) {
	if st == nil || st.Mode != vpnsvc.ModeBlack || st.Online {
		return nil, ""
	}
	if wait > 0 {
		return nil, humanSeconds(int64((wait + time.Second - 1) / time.Second))
	}
	return &ui.ActionForm{Action: "/vpn/reconnect", CSRF: csrf,
		Button: ui.Button{Label: "Переподключить сейчас", Icon: "refresh"}}, ""
}
