package vpndiag

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

type Level string

const (
	LevelOK    Level = "ok"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Facts struct {
	ModeBlack       bool
	Present         bool
	Online          bool
	Degraded        bool
	HandshakeEver   bool
	HandshakeAgeSec int64
	FullTunnel      bool

	DataPlane vpndriver.Truth

	Cores int
	Load1 float64

	TariffDownKbit    int
	TariffUpKbit      int
	ShapedTunDownKbit int
	ShapedTunUpKbit   int
	QueueDropped      int64

	DirectDownKbit int
	DirectUpKbit   int
	TunnelDownKbit int
	TunnelUpKbit   int

	SampleSize int

	SampleMin      int
	ServiceLossPct float64
	DataLossPct    float64
	RTTBaselineMs  float64
	RTTTunnelMs    float64

	MTU       int
	Blackhole bool

	DirectProbed  bool
	DirectAnswers bool

	ConfigDNS string

	Protocol        string
	Transport       string
	KernelDataPlane bool

	ProcState  string
	FailReason string
	FailCount  int

	RetryPaused bool
	RetryInSec  int64

	SelfHealing bool

	DataStuck   bool
	DataSuspect bool

	OutboundGuard   bool
	BlockedOutbound int64

	UnderLoad       bool
	IdleDataLossPct float64
}

type Finding struct {
	Level  Level
	Code   string
	Title  string
	Text   string
	Action string
}

const (
	minSample = 1000

	shaperNearPct = 90

	pathSuspectPct = 60

	latencyNeutralMs = 10.0

	latencyTunnelCostMs = 20.0

	lossUnderLoadPP = 1.0

	lossCalmPP = 1.0

	lossWebOnlyPP = 3.0

	serviceGapPP = 1.0
)

func Analyze(f Facts) []Finding {
	var out []Finding
	add := func(fn ...Finding) { out = append(out, fn...) }

	add(stateFindings(f)...)
	add(speedFindings(f)...)
	add(qualityFindings(f)...)
	add(configFindings(f)...)
	add(protocolFindings(f)...)
	add(guardFindings(f)...)
	add(loadFindings(f)...)
	add(calmLossFindings(f)...)

	order := map[Level]int{LevelError: 0, LevelWarn: 1, LevelInfo: 2, LevelOK: 3}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && order[out[j].Level] < order[out[j-1].Level]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func State(f Facts) (Finding, bool) {
	found := stateFindings(f)
	if len(found) == 0 {
		return Finding{}, false
	}
	return found[0], true
}

func stateFindings(f Facts) []Finding {
	if !f.ModeBlack {
		return nil
	}
	switch {
	case f.Degraded:
		return []Finding{{Level: LevelError, Code: "released",
			Title:  "Офис сейчас выходит в интернет напрямую",
			Text:   "Защищённый канал не отвечает, и по вашей настройке «выпускать напрямую» офис работает без него. Пока это так, трафик и адреса сайтов видны провайдеру.",
			Action: "Ничего делать не нужно: панель сама вернёт защиту, как только канал оживёт. Если это затянулось — проверьте, действует ли подключение у поставщика."}}
	case f.Present && f.Online && f.DataStuck:
		return []Finding{{Level: LevelError, Code: "data_stuck",
			Title:  "Канал подключён, но данные через него не проходят",
			Text:   "Соединение с сервером подключения есть, а проверочные запросы сквозь канал остаются без ответа. Панель дважды подключила канал заново — не помогло. Причина на стороне сервера подключения.",
			Action: "Обратитесь к поставщику подключения: сервер принимает подключение, но не пропускает данные. После исправления нажмите «Применить»."}}
	case f.Present && f.Online && f.DataPlane.IsNo():
		return []Finding{{Level: LevelError, Code: "data_dead",
			Title:  "Канал установлен, но данные через него не идут",
			Text:   "Соединение с сервером есть, а обычный запрос сквозь канал не проходит. Чаще всего это значит, что файл подключения рассчитан на канал с особыми настройками — например, с маскировкой трафика.",
			Action: "Запросите у поставщика обычную конфигурацию. Если файл наш — обратитесь в поддержку: это не поломка вашей сети."}}
	case f.Present && !f.Online && f.HandshakeEver:
		return []Finding{{Level: LevelError, Code: "handshake_lost",
			Title:  "Связь с сервером подключения пропала",
			Text:   "Канал поднят, но сервер перестал отвечать. Офис остаётся без интернета — так и задумано: трафик не выпускается в обход канала.",
			Action: "Проверьте, что сервер видит интернет и что подключение у поставщика ещё действует. Панель повторяет попытки сама."}}
	case f.FailReason != "" && !f.Online:
		return []Finding{processFailure(f)}
	case f.Present && !f.HandshakeEver:
		return []Finding{handshakeNever(f)}
	case !f.Present && f.SelfHealing && !f.RetryPaused:
		return []Finding{{Level: LevelError, Code: "reconnecting",
			Title:  "Канал переподключается",
			Text:   "Связь с сервером подключения прервалась, и программа канала подключается заново сама. Пока она не подключилась, офис без интернета — так и задумано: трафик не выпускается в обход канала.",
			Action: "Обычно канал возвращается сам за минуту. Если это затянулось — проверьте, что сервер доступен и подключение у поставщика действует."}}
	case !f.Present:
		fin := Finding{Level: LevelError, Code: "no_tunnel",
			Title:  "Защищённый канал не поднят",
			Text:   "Режим выбран, но канала нет.",
			Action: "Нажмите «Применить» ещё раз; если не помогает — обратитесь в поддержку."}

		if f.RetryPaused {
			fin.Text += " Канал не поднялся после нескольких попыток подряд, и панель прекратила автоматические попытки — следующая за вами."
		}
		return []Finding{fin}
	}
	if f.Present && f.Online && f.DataSuspect {
		return []Finding{{Level: LevelWarn, Code: "data_suspect",
			Title:  "Похоже, ответы через канал не приходят",
			Text:   "Офис отправляет данные через канал, а ответов не приходит. Проверить это сама панель сейчас не может: сбор показателей выключен, и проба пути не работает.",
			Action: "Нажмите «Проверить защищённый канал» ниже или включите сбор показателей — тогда панель будет проверять канал сама и при необходимости подключит его заново."}}
	}
	return []Finding{{Level: LevelOK, Code: "tunnel_ok",
		Title: "Защищённый канал работает",
		Text:  "Соединение с сервером есть, данные через канал проходят."}}
}

func handshakeNever(f Facts) Finding {
	const clock = "Отдельный случай: если часы СПЕШИЛИ и их уже поправили, сервер поставщика ещё какое-то время будет отклонять подключение — он запомнил время из будущего и защищается от повторов. Тогда канал поднимется сам, когда настоящее время догонит."
	fin := Finding{Level: LevelError, Code: "handshake_never",
		Title:  "Сервер подключения ни разу не ответил",
		Action: "Нажмите «Проверить время сервера» ниже на этой странице — она спросит точное время в обход канала и при необходимости поправит часы. Если время верное, а канал молчит, запросите у поставщика свежий файл подключения и проверьте, действует ли оно; при необходимости попросите перезапустить его на своей стороне."}
	switch {
	case f.DirectProbed && f.DirectAnswers:
		fin.Text = "Сервер отвечает на проверку мимо канала, но подключение не принимает — значит, дело не в адресе и не в пути. Чаще всего ключ в файле больше не подходит серверу (поставщик сменил ключи или загружен старый файл); реже — подключение у поставщика закончилось либо часы сервера расходятся с настоящим временем. " + clock
	case f.DirectProbed && !f.DirectAnswers:
		fin.Text = "Сервер не отвечает и на проверку мимо канала. Чаще всего это значит, что адрес или порт сервера изменились либо путь к нему закрыт провайдером; реже сервер просто не отвечает на такие проверки — тогда причина может быть в ключе, сроке подключения или часах. " + clock
	default:
		fin.Text = "Канал поднят, но обмена с сервером не было ни разу. Обычные причины: ключ в файле больше не подходит серверу (поставщик сменил ключи или загружен старый файл), подключение у поставщика закончилось, адрес или порт сервера изменились, либо часы сервера расходятся с настоящим временем — при большом расхождении сервер отказывается принимать подключение. " + clock +
			" Нажмите «Проверить защищённый канал» ниже: проба мимо канала покажет, отвечает ли сервер вообще, и сузит причину."
	}
	return fin
}

func processFailure(f Facts) Finding {
	const clock = " Отдельный случай: если часы СПЕШИЛИ и их уже поправили, сервер поставщика ещё какое-то время будет отклонять подключение — он запомнил время из будущего и защищается от повторов."

	pause := ""
	if f.RetryPaused {
		pause = " Панель прекратила автоматические попытки подключения: повторять с тем же файлом бесполезно. " +
			"Исправьте причину и нажмите «Применить» — панель попробует снова."
	}
	fin := Finding{Level: LevelError}
	switch f.FailReason {
	case "tls_verify_failed":
		fin.Code, fin.Title = "file_rejected_tls", "Сервер отверг сертификаты или ключ из файла"
		fin.Text = "Сервер ответил, но проверка сертификатов не сошлась: файл выдан для другого сервера, поставщик обновил сертификаты, либо часы сервера расходятся с настоящим временем." + clock + pause
		fin.Action = "Сначала нажмите «Проверить время сервера» ниже на этой странице. Если время верное — запросите у поставщика свежий файл подключения и загрузите его заново."
	case "cert_rejected":
		fin.Code, fin.Title = "cert_rejected", "Сервер не принимает ваш сертификат"
		fin.Text = "Сервер проверен, но сертификат из файла он не принял: файл выдан другому клиенту, отозван поставщиком или срок его действия истёк." + pause
		fin.Action = "Запросите у поставщика свежий файл подключения и загрузите его заново."
	case "rejected_after_tls":
		fin.Code, fin.Title = "rejected_after_tls", "Сервер отверг подключение после проверки"
		fin.Text = "Проверка сертификатов прошла, но сервер отказал: у файла и сервера нет общего способа шифрования либо сервер требует данные, которых в файле нет (например, логин и пароль)." + pause
		fin.Action = "Запросите у поставщика современный файл подключения без логина и пароля."
	default:
		fin.Code, fin.Title = "server_silent", "Сервер подключения не отвечает"
		fin.Text = "Сервер не отвечает на попытки подключения. Обычно это значит, что изменились адрес, порт или транспорт сервера либо путь к нему закрыт провайдером; реже — ключ обёртки в файле не совпадает с сервером, и тогда сервер молчит намеренно." + pause
		switch {
		case f.DirectProbed && f.DirectAnswers:
			fin.Text += " Проверка мимо канала показала: сервер жив и отвечает — значит, дело в порте, транспорте или ключе обёртки из файла, а не в адресе и не в пути."
		case f.DirectProbed && !f.DirectAnswers:
			fin.Text += " Проверка мимо канала показала: сервер не отвечает и на неё — вероятнее всего, адрес изменился или путь закрыт."
		}
		fin.Action = "Нажмите «Проверить защищённый канал»: проба мимо канала покажет, отвечает ли сервер вообще. Сверьте у поставщика адрес, порт и транспорт из файла и запросите свежий файл, если они изменились."
	}
	if f.FailCount > 1 {
		fin.Text += fmt.Sprintf(" Неудачных попыток подряд: %d.", f.FailCount)
	}
	return fin
}

func protocolFindings(f Facts) []Finding {
	if !f.ModeBlack {
		return nil
	}
	var out []Finding
	if f.Transport == "tcp" {
		out = append(out, Finding{Level: LevelWarn, Code: "transport_tcp",
			Title: "Подключение работает по TCP — для разговоров не годится",
			Text: "Голос идёт потоком мелких пакетов, и потеря одного из них безвредна. Поверх TCP потерянный пакет задерживает всё, что идёт следом, и разговор рвётся даже на хорошем канале. " +
				"Для работы в интернете такое подключение годится, и там, где UDP не проходит, оно единственное рабочее.",
			Action: "Для телефонии запросите у поставщика подключение по UDP и выберите его; это подключение оставьте для обычной работы в интернете."})
	}
	if f.Present && !f.KernelDataPlane {
		out = append(out, Finding{Level: LevelInfo, Code: "userspace_crypto",
			Title:  "Шифрование канала выполняет процесс, а не ядро сервера",
			Text:   "Модуль ядра для этого типа канала на сервере недоступен, и каждый пакет проходит через процесс. Канал работает, но при больших закачках нагрузка на процессор выше, и разговоры могут пострадать раньше.",
			Action: "Ничего делать не нужно. Если разговоры страдают при закачках — следите за нагрузкой процессора на этой странице и рассмотрите более мощный сервер."})
	}
	return out
}

func guardFindings(f Facts) []Finding {
	if !f.ModeBlack {
		return nil
	}
	if !f.OutboundGuard {
		return []Finding{{Level: LevelWarn, Code: "outbound_guard_off",
			Title: "Защита выхода самого сервера не включена",
			Text: "Офис выходит через канал, а программы самого сервера могут ходить в интернет напрямую — так делает, например, штатная проверка связи. " +
				"Каждая такая попытка сообщает провайдеру, что офис работает, и его публичный адрес.",
			Action: "Нажмите «Применить» на этой странице — защита включится вместе с настройками."}}
	}
	if f.BlockedOutbound <= 0 {
		return nil
	}
	return []Finding{{Level: LevelInfo, Code: "outbound_blocked",
		Title: fmt.Sprintf("Панель заблокировала %d %s выйти в интернет мимо канала",
			f.BlockedOutbound, plural(f.BlockedOutbound, "попытку", "попытки", "попыток")),
		Text: "Так ведут себя штатные программы сервера: проверка связи, объявление имени сервера соседям по сети провайдера, обратные запросы имён. " +
			"Каждая из них выдала бы провайдеру факт работы офиса и его публичный адрес, поэтому панель их не выпускает. Это нормальная работа защиты, а не поломка.",
		Action: "Ничего делать не нужно. Если какая-то программа на самом сервере перестала работать после включения защищённого режима — сообщите в поддержку, это может быть причиной."}}
}

func plural(n int64, one, few, many string) string {
	if n < 0 {
		n = -n
	}
	if n%100 >= 11 && n%100 <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	}
	return many
}

func speedFindings(f Facts) []Finding {
	if f.TunnelDownKbit == 0 || f.DirectDownKbit == 0 {
		return nil
	}
	var out []Finding
	dropPct := 100 - f.TunnelDownKbit*100/f.DirectDownKbit

	if f.ShapedTunDownKbit > 0 && f.TunnelDownKbit*100 >= f.ShapedTunDownKbit*shaperNearPct {
		out = append(out, Finding{Level: LevelInfo, Code: "our_shaper",
			Title: "Скорость ограничена настройкой приоритета трафика — это не поломка",
			Text: fmt.Sprintf("Панель намеренно держит канал чуть ниже указанного тарифа (%d Мбит/с), чтобы очередь копилась на вашем сервере, а не у провайдера — именно так звонки остаются чистыми при закачках. Замер (%d Мбит/с) упёрся в этот потолок.",
				f.TariffDownKbit/1000, f.TunnelDownKbit/1000),
			Action: "Если тариф на самом деле выше — исправьте его на странице «Приоритет трафика», и потолок поднимется."})
		return out
	}

	if dropPct < 20 {
		return out
	}

	if f.QueueDropped > 0 {
		out = append(out, Finding{Level: LevelWarn, Code: "our_queue_drops",
			Title:  "Часть пакетов отброшена очередью самого сервера",
			Text:   fmt.Sprintf("За время замера очереди сервера отбросили %d пакетов. Обычно это значит, что указанный тариф выше настоящего канала.", f.QueueDropped),
			Action: "Запустите замер скорости на странице «Приоритет трафика» и подставьте измеренные значения."})
	}

	if f.Cores > 0 && f.Load1 > float64(f.Cores)*0.8 {
		out = append(out, Finding{Level: LevelWarn, Code: "cpu_bound",
			Title:  "Процессору сервера не хватает мощности на шифрование",
			Text:   fmt.Sprintf("Во время замера сервер был загружен (%.2f при %d ядрах). Шифрование канала считает процессор, и он стал узким местом.", f.Load1, f.Cores),
			Action: "Более мощный сервер снимет ограничение. Звонки при этом страдают первыми — не откладывайте."})
	}

	if f.QueueDropped == 0 && dropPct >= (100-pathSuspectPct) {
		out = append(out, Finding{Level: LevelWarn, Code: "path_ceiling",
			Title: "Скорость ограничена не сервером, а путём до поставщика",
			Text: fmt.Sprintf("Без канала — %d Мбит/с, через канал — %d Мбит/с (на %d %% меньше). При этом очереди вашего сервера не отбросили ни одного пакета, и процессор не был загружен: всё, что выше, теряется по дороге к серверу поставщика.",
				f.DirectDownKbit/1000, f.TunnelDownKbit/1000, dropPct),
			Action: "Это ограничение самого подключения, а не вашей сети и не панели. Попросите у поставщика сервер ближе к вам или тариф с большей полосой."})
	}
	return out
}

func calmLossFindings(f Facts) []Finding {
	if !f.ModeBlack || f.UnderLoad || f.SampleSize == 0 {
		return nil
	}
	loss := f.DataLossPct
	if f.ServiceLossPct > loss {
		loss = f.ServiceLossPct
	}
	if loss < lossUnderLoadPP {
		return nil
	}
	return []Finding{{Level: LevelWarn, Code: "calm_loss",
		Title: fmt.Sprintf("Канал теряет %.1f %% пакетов даже без нагрузки", loss),
		Text: "Проверка шла на спокойном канале: большие закачки в это время не выполнялись. " +
			"Потери такого размера слышны в разговоре как провалы, а страницы открываются рывками. " +
			"Причина не в загрузке вашего канала — теряет либо путь до сервера поставщика, либо сам сервер.",
		Action: "Повторите проверку через несколько минут: короткие всплески потерь бывают у любого провайдера. " +
			"Если потери держатся — запросите у поставщика другой сервер, ваш шлюз тут ни при чём."}}
}

func loadFindings(f Facts) []Finding {
	if !f.ModeBlack || !f.UnderLoad {
		return nil
	}
	loss := f.DataLossPct
	if f.ServiceLossPct > loss {
		loss = f.ServiceLossPct
	}
	if loss < lossUnderLoadPP || f.SampleSize == 0 {
		return nil
	}

	var out []Finding

	ourCeiling := f.ShapedTunDownKbit > 0 && f.TunnelDownKbit > 0 &&
		f.TunnelDownKbit*100 >= f.ShapedTunDownKbit*shaperNearPct
	switch {
	case ourCeiling:
		out = append(out, Finding{Level: LevelWarn, Code: "load_our_ceiling",
			Title: fmt.Sprintf("Во время закачки разговор теряет %.1f %% пакетов — упираемся в наш потолок", loss),
			Text: fmt.Sprintf("Закачка вышла на %d Мбит/с при нашем потолке %d Мбит/с: очередь сервера работает и держит задержку, но полоса кончилась.",
				f.TunnelDownKbit/1000, f.ShapedTunDownKbit/1000),
			Action: "Проверьте, что тариф на странице «Приоритет трафика» указан верно. Если он занижен — исправьте; если верен, во время разговоров придётся ограничивать большие закачки."})
	default:
		out = append(out, Finding{Level: LevelWarn, Code: "load_path_bottleneck",
			Title: fmt.Sprintf("Во время закачки разговор теряет %.1f %% пакетов, и это не ваш сервер", loss),
			Text: fmt.Sprintf("Закачка через канал вышла лишь на %d Мбит/с при нашем потолке %d Мбит/с — значит очередь вашего сервера узким местом не была; за время проверки она отбросила %d пакетов, процессор был свободен. Пакеты пропадают дальше — на сервере поставщика или на пути к нему, куда настройки вашего шлюза не дотягиваются.",
				f.TunnelDownKbit/1000, f.ShapedTunDownKbit/1000, f.QueueDropped),
			Action: "Снижать тариф бесполезно и вредно — проверено: потери от этого растут. Либо не запускать большие закачки во время разговоров, либо запросить у поставщика сервер, пригодный для телефонии. Настоящий разговор шлёт пакеты в десять раз чаще проверки, поэтому теряет обычно больше показанного."})
	}

	if f.IdleDataLossPct > 0 && f.IdleDataLossPct < lossCalmPP && loss >= lossWebOnlyPP {
		out = append(out, Finding{Level: LevelInfo, Code: "server_web_not_calls",
			Title: "Это подключение годится для работы в интернете, но не для разговоров во время закачек",
			Text: fmt.Sprintf("На спокойном канале потери %.2f %%, под полной закачкой — %.1f %%. Сайты и почта такого не замечают, разговор — замечает сразу.",
				f.IdleDataLossPct, loss),
			Action: "Для телефонии запросите у поставщика подключение к серверу с запасом полосы, а это оставьте для обычной работы в интернете."})
	}
	return out
}

func qualityFindings(f Facts) []Finding {
	var out []Finding

	limit := f.SampleMin
	if limit <= 0 {
		limit = minSample
	}
	if f.SampleSize > 0 && f.SampleSize < limit {
		out = append(out, Finding{Level: LevelInfo, Code: "sample_small",
			Title:  "Замер слишком короткий, чтобы делать выводы",
			Text:   fmt.Sprintf("Получено %d измерений при нужных %d. На такой выборке одна потеря превращается в проценты — именно поэтому индикаторы качества в программах для звонков часто краснеют без причины.", f.SampleSize, limit),
			Action: "Повторите проверку — она должна идти не меньше двадцати секунд."})
		return out
	}

	if f.SampleSize >= limit && f.ServiceLossPct-f.DataLossPct >= serviceGapPP && f.DataLossPct < 0.5 {
		out = append(out, Finding{Level: LevelInfo, Code: "icmp_deprioritized",
			Title: "Красный индикатор в программе для звонков — не всегда признак плохого звука",
			Text: fmt.Sprintf("По одному и тому же пути служебные пакеты теряются на %.1f %%, а обычные данные — на %.2f %%. Узлы связи намеренно обслуживают служебные пакеты в последнюю очередь: это защита от перебора адресов, а не поломка. Программы для звонков часто судят о качестве именно по ним.",
				f.ServiceLossPct, f.DataLossPct),

			Action: "Если разговоры при этом рвутся по-настоящему, дело не в индикаторе: запустите полную проверку во время закачки — она показывает, как канал ведёт себя под нагрузкой."})
	}

	if f.RTTBaselineMs > 0 && f.RTTTunnelMs > 0 {
		delta := f.RTTTunnelMs - f.RTTBaselineMs

		if delta >= latencyTunnelCostMs {
			out = append(out, Finding{Level: LevelWarn, Code: "latency_tunnel_cost",
				Title: fmt.Sprintf("Канал добавляет %.0f мс задержки", delta),
				Text: fmt.Sprintf("До сервера подключения мимо канала — %.0f мс, через канал до него же — %.0f мс. Оба числа сняты одновременно и до одной машины, значит дело не в расстоянии и не в вашей сети: столько стоит обработка на стороне поставщика. Чаще всего так выглядит загруженный сервер в часы пик.",
					f.RTTBaselineMs, f.RTTTunnelMs),
				Action: "Повторите проверку в другое время суток. Если разница держится постоянно — попросите у поставщика другой сервер: на разговорах это слышно."})
		}
		if delta < latencyNeutralMs && f.RTTTunnelMs > 40 {
			out = append(out, Finding{Level: LevelInfo, Code: "latency_geography",
				Title: "Задержка — это расстояние до сервера, а не защищённый канал",
				Text: fmt.Sprintf("Задержка через канал %.0f мс, а до того же сервера без канала — %.0f мс. Сам канал добавил меньше %.0f мс: остальное — путь до города, где стоит сервер поставщика.",
					f.RTTTunnelMs, f.RTTBaselineMs, latencyNeutralMs),
				Action: "Если задержка мешает разговорам, поможет только сервер поставщика ближе к вам."})
		}
	}

	if f.Blackhole {
		out = append(out, Finding{Level: LevelWarn, Code: "mtu_blackhole",
			Title:  "Крупные пакеты по пути пропадают",
			Text:   "Мелкие пакеты проходят, крупные молча теряются. Из-за этого сайты начинают открываться и «зависают», а звонок может не устанавливаться при живой регистрации телефона.",
			Action: "Нажмите «Подобрать размер пакетов» — панель измерит путь и предложит рабочее значение."})
	}
	return out
}

func configFindings(f Facts) []Finding {
	var out []Finding
	if f.ModeBlack && !f.FullTunnel {
		out = append(out, Finding{Level: LevelWarn, Code: "split_tunnel",
			Title:  "Файл подключения направляет в канал не весь трафик",
			Text:   "В таком файле часть адресов идёт мимо канала. Обещание «весь офис защищён» с ним не выполняется.",
			Action: "Запросите у поставщика конфигурацию, направляющую в канал весь трафик."})
	}
	if f.ModeBlack && f.ConfigDNS != "" {
		out = append(out, Finding{Level: LevelInfo, Code: "config_dns",
			Title:  "Файл просит свой сервер имён — панель его не применяет",
			Text:   fmt.Sprintf("Файл подключения указывает сервер имён «%s». Именами в офисе распоряжается резолвер вашего сервера, и в защищённом режиме его запросы не покидают канал.", f.ConfigDNS),
			Action: "Если поставщик настаивает на своём сервере имён — переключите выбор в расширенных настройках."})
	}
	return out
}

const (
	VoiceLossLimitPct = lossCalmPP

	WebOnlyLossPct = lossWebOnlyPP
)
