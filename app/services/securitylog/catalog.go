package securitylog

import (
	"sort"
	"time"
)

type Class string

const (
	Critical Class = "критичное"

	Ordinary Class = "обычное"

	System Class = "системное"
)

type Entry struct {
	Title string
	Class Class

	Failure bool

	Alarm bool

	Break bool

	Notice string
}

const UnknownTitle = "Системное событие"

func critical(title string) Entry { return Entry{Title: title, Class: Critical} }
func ordinary(title string) Entry { return Entry{Title: title, Class: Ordinary} }
func system(title string) Entry   { return Entry{Title: title, Class: System} }
func failed(title string) Entry   { return Entry{Title: title, Class: Critical, Failure: true} }
func alarm(title string) Entry    { return Entry{Title: title, Class: System, Alarm: true} }

func unattended(title, notice string) Entry {
	return Entry{Title: title, Class: Critical, Failure: true, Notice: notice}
}

var catalog = map[string]Entry{
	"setup_completed":      critical("Учётная запись администратора создана"),
	"setup_finished":       critical("Мастер первой настройки закрыт"),
	"setup_denied":         ordinary("Отказ мастеру установки"),
	"setup_code_issued":    critical("Выдан установочный код"),
	"code_issued":          critical("Выдан код подключения"),
	"code_failed":          ordinary("Введён неверный код"),
	"device_enrolled":      critical("Устройство подключено"),
	"device_revoked":       critical("Доступ устройства отозван"),
	"device_signed_out":    critical("Выход из панели"),
	"devices_signed_out":   critical("Выход на всех остальных устройствах"),
	"devices_reset":        critical("Сброс всех устройств"),
	"device_new_ip":        critical("Устройство сменило адрес"),
	"network_apply":        critical("Настройки сети применены"),
	"network_apply_failed": failed("Настройки сети не применились"),
	"network_confirmed":    critical("Настройки сети закреплены"),
	"network_rolled_back":  failed("Настройки сети откачены"),
	"network_unconfirmed": unattended("Изменение сети не подтверждено",
		"Изменение сети не было подтверждено (истёк срок или пропадало питание): действуют прежние настройки. Если изменение нужно — повторите его на странице «Сеть»."),
	"settings_import":             critical("Настройки загружены из файла"),
	"settings_import_confirmed":   critical("Настройки из файла закреплены"),
	"settings_import_rolled_back": failed("Настройки из файла откачены"),
	"settings_import_expired": unattended("Настройки из файла не подтверждены в срок",
		"Настройки из файла не были подтверждены в срок и откачены: действуют настройки до импорта. Если импорт нужен — повторите его на странице «Резервная копия» и подтвердите."),
	"settings_import_broken": unattended("Импорт прерван обрывом питания",
		"Импорт настроек прервался обрывом питания до начала изменений: действуют прежние настройки. Проверьте их и при необходимости повторите импорт на странице «Резервная копия»."),
	"settings_export":             critical("Настройки выгружены в файл"),
	"support_collected":           critical("Собраны сведения для поддержки"),
	"firewall_apply":              critical("Раздача интернета и защита применены"),
	"firewall_apply_failed":       failed("Раздача интернета и защита не применились"),
	"dns_apply":                   critical("Разрешение имён настроено"),
	"dns_apply_failed":            failed("Разрешение имён не настроилось"),
	"dhcp_apply":                  critical("Раздача адресов настроена"),
	"dhcp_apply_failed":           failed("Раздача адресов не настроилась"),
	"qos_apply":                   critical("QoS применён"),
	"qos_apply_failed":            failed("QoS не применился"),
	"host_reapply":                system("Настройки раздела обновлены под новые версии программ системы"),
	"dhcp_waits_foreign":          alarm("Раздача адресов ждёт: на карте офиса работает другая служба"),
	"network_waits_foreign":       alarm("Сеть не применена: на карте офиса раздаёт адреса другая служба"),
	"network_waits_legacy":        alarm("Сеть не применена: старый скрипт vpn.sh меняет систему"),
	"http_port_found":             alarm("Порт 80 на сервере занят другой программой"),
	"http_port_cleared":           system("Порт 80 на сервере освободился"),
	"tls_port_found":              alarm("Порт панели занят другой программой"),
	"tls_port_cleared":            system("Порт панели освободился"),
	"foreign_dhcp_found":          alarm("На сервере работает другая служба раздачи адресов"),
	"foreign_dhcp_cleared":        system("Другая служба раздачи адресов больше не работает"),
	"forward_boot_found":          alarm("Настройки системы включают пересылку раньше защиты"),
	"forward_boot_cleared":        system("Настройки системы больше не включают пересылку раньше защиты"),
	"lan_dhcp_found":              alarm("В сети офиса работает ещё один сервер раздачи адресов"),
	"lan_dhcp_cleared":            system("Второй сервер раздачи адресов в сети офиса больше не отвечает"),
	"forward_cut_found":           alarm("Чужие правила фаервола режут интернет офиса"),
	"forward_cut_cleared":         system("Чужие правила фаервола больше не режут интернет офиса"),
	"forward_off_found":           alarm("Другая программа выключила пересылку трафика"),
	"forward_off_cleared":         system("Пересылку трафика больше никто не выключает"),
	"own_table_found":             alarm("Другая программа стёрла правила шлюза"),
	"own_table_cleared":           system("Правила шлюза больше никто не стирает"),
	"legacy_found":                alarm("Найден шлюз старого скрипта vpn.sh"),
	"legacy_cleared":              system("Шлюз старого скрипта vpn.sh больше не найден"),
	"legacy_sudo_found":           alarm("Найдено: веб-сервер может выполнять любые команды администратора"),
	"legacy_sudo_cleared":         system("Веб-сервер больше не может выполнять любые команды администратора"),
	"legacy_root_service_found":   alarm("Найдена служба администратора в открытой папке"),
	"legacy_root_service_cleared": system("Служба администратора в открытой папке больше не найдена"),
	"legacy_terminal_found":       alarm("Найден терминал в браузере"),
	"legacy_terminal_cleared":     system("Терминал в браузере выключен"),
	"legacy_usb_found":            alarm("Найден автозапуск с флешки"),
	"legacy_usb_cleared":          system("Автозапуск с флешки снят"),
	"legacy_keys_found":           alarm("Файлы подключения VPN читаются не только системой"),
	"legacy_keys_cleared":         system("Файлы подключения VPN снова закрыты"),
	"legacy_pppoe_found":          alarm("Старый скрипт vpn.sh сам поднимает PPPoE"),
	"legacy_pppoe_cleared":        system("Старый скрипт vpn.sh больше не поднимает PPPoE"),
	"legacy_tunnel_found":         alarm("Работает канал старого скрипта vpn.sh"),
	"legacy_tunnel_cleared":       system("Канал старого скрипта vpn.sh остановлен"),
	"legacy_rerun": {Title: "Старый скрипт vpn.sh запускали поверх панели", Class: System, Alarm: true,
		Notice: "Старый скрипт vpn.sh запускали поверх панели: он заменил её настройки сети своими. Откройте «Диагностику» — там видно, что найдено на сервере. Не запускайте старый скрипт поверх панели."},
	"security_settings":         critical("Изменены настройки защиты"),
	"auto_updates":              critical("Изменены автоматические обновления"),
	"disk_change":               critical("Запрошена или отменена смена пароля диска"),
	"panel_upgraded":            critical("Панель обновилась"),
	"release_accept":            critical("Владелец оставил новую версию панели"),
	"device_label_proposed":     ordinary("Сотрудник предложил подпись устройства"),
	"device_label_throttled":    ordinary("Слишком частые предложения подписи"),
	"device_label_accepted":     critical("Подпись устройства принята"),
	"device_label_rejected":     critical("Предложение подписи отклонено"),
	"device_label_set":          critical("Подпись устройства изменена"),
	"diag_probe":                critical("Проверка сети офиса выполнена"),
	"diag_probe_failed":         failed("Проверка сети офиса не запустилась"),
	"diag_lantest":              ordinary("Тест скорости до сервера"),
	"diag_lantest_started":      ordinary("Запущен тест скорости до сервера"),
	"device_identify_requested": ordinary("Сотрудник сообщил, что он за этим компьютером"),
	"device_identify_closed":    critical("Сообщение «это мой компьютер» закрыто"),
	"lan_window_opened":         critical("Открыто окно проверок скорости"),
	"lan_window_extended":       critical("Продлено окно проверок скорости"),
	"lan_window_closed":         critical("Закрыто окно проверок скорости"),
	"lan_window_limit":          critical("Изменён предел срока окна проверок"),
	"lan_fullcheck_started":     critical("Начата полная проверка сети: пределы сняты"),
	"lan_fullcheck_stopped":     critical("Полная проверка сети остановлена администратором"),
	"lan_fullcheck_ended":       critical("Полная проверка сети закончилась по сроку"),
	"diag_settings":             critical("Изменены настройки диагностики"),
	"vpn_import":                critical("Добавлено подключение к защищённому каналу"),
	"vpn_direct_probe":          critical("Замер прямого плеча: выход мимо защищённого канала"),
	"vpn_import_failed":         critical("Файл подключения не принят"),
	"vpn_leak_detected":         failed("Утечка мимо защищённого канала"),
	"vpn_intent_broken": unattended("Настройки защищённого канала повреждены",
		"Настройки защищённого канала перестали читаться (сбой диска или питания). Чтобы трафик офиса не пошёл мимо канала, офис закрыт от интернета или будет закрыт после перезагрузки. Откройте страницу «VPN», проверьте режим и нажмите «Применить»."),
	"vpn_apply":             critical("Режим защищённого канала применён"),
	"vpn_apply_failed":      failed("Режим защищённого канала не применился"),
	"vpn_remove":            critical("Подключение удалено"),
	"vpn_reconnect":         critical("Переподключение канала вручную"),
	"vpn_reconnect_failed":  failed("Переподключение вручную не принято"),
	"vpn_remove_failed":     failed("Подключение не удалось удалить"),
	"vpn_mtu_probe":         critical("Подобран размер пакетов"),
	"vpn_mtu_probe_failed":  failed("Подбор размера пакетов не удался"),
	"vpn_probe_target":      critical("Изменена цель пробы внутри канала"),
	"path_target":           system("Выбрана цель пробы внутри канала"),
	"path_target_rejected":  system("Кандидат цели пробы отвергнут"),
	"path_tunnel_up":        system("Канал доступен"),
	"path_tunnel_down":      system("Обрыв канала"),
	"path_tunnel_no_answer": system("Цель пробы внутри канала не отвечает"),
	"path_beyond_up":        system("Интернет через канал доступен"),
	"path_beyond_down":      system("Интернет через канал недоступен"),
	"path_beyond_no_answer": system("Цель за сервером канала не отвечает"),
	"path_direct_up":        system("Прямой доступ работает"),
	"path_direct_down":      system("Прямой доступ пропал"),
	"path_direct_no_answer": system("Цель прямого доступа не отвечает"),
	"panel_crashed":         {Title: "Панель завершилась аварийно и запущена заново", Class: System, Failure: true, Break: true},
	"unclean_shutdown":      {Title: "Прошлая загрузка сервера закончилась без штатной остановки", Class: System, Failure: true, Break: true},
	"time_sync":             critical("Проверено время сервера"),
	"time_sync_failed":      failed("Время сервера проверить не удалось"),
	"devices_new_throttled": ordinary("Слишком много новых устройств за час"),
	"retention_settings":    critical("Изменены сроки хранения данных"),
	"disk_budget":           critical("Изменён бюджет диска панели"),
	"disk_low":              critical("На диске сервера мало места"),
	"disk_critical":         critical("На диске сервера почти нет места"),
	"syslog_cap":            critical("Изменено ограничение системных журналов"),
	"syslog_trimmed":        critical("Системные журналы обрезаны"),
	"overload_started":      ordinary("Панель перегружена: часть запросов отклоняется"),
	"overload_ended":        ordinary("Перегрузка панели закончилась"),
	"metrics_master":        {Title: "Изменён рубильник сбора показателей", Class: Critical, Break: true},
	"metrics_source":        {Title: "Изменено состояние источника показателей", Class: Critical, Break: true},
	"metrics_source_paused": {Title: "Источник показателей приостановлен предохранителем", Class: Critical, Break: true},
}

func Lookup(code string) (Entry, bool) {
	e, ok := catalog[code]
	return e, ok
}

func Title(code string) string {
	if e, ok := catalog[code]; ok {
		return e.Title
	}
	return UnknownTitle
}

func ClassOf(code string) Class {
	if e, ok := catalog[code]; ok {
		return e.Class
	}
	return Critical
}

func Codes(match func(Entry) bool) []string {
	var out []string
	for code, e := range catalog {
		if match(e) {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

func CodesOf(c Class) []string { return Codes(func(e Entry) bool { return e.Class == c }) }

func FailureCodes() []string { return Codes(func(e Entry) bool { return e.Failure }) }

func BreakCodes() []string { return Codes(func(e Entry) bool { return e.Break }) }

func SystemCap(days int) int {
	return len(CodesOf(System)) * int(24*time.Hour/DedupWindow) * days
}
