package settings

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Key struct {
	Name    string
	Prefix  bool
	Section Section
	Data    Data
	Risk    Risk

	Why string

	Title, Warn string

	Owner Owner

	RefersTo Owner
}

type Owner string

const (
	OwnerVPNProfile    Owner = "профиль канала"
	OwnerMetricsSource Owner = "источник метрик"
)

var owners = []Owner{OwnerVPNProfile, OwnerMetricsSource}

type Table struct {
	Name    string
	Section Section
	Data    Data
	Risk    Risk
	Why     string

	Title, Warn string

	Owner Owner
}

var Keys = []Key{
	{Name: "network.confirm_timeout_sec", Section: SectionNetwork, Data: Policy, Risk: Safe},
	{Name: "network.applied_lans", Section: SectionNetwork, Data: State, Risk: Safe},
	{Name: "network.pending_apply", Section: SectionNetwork, Data: State, Risk: Safe},
	{Name: "network.import_until", Section: SectionNetwork, Data: State, Risk: Safe},
	{Name: "network.import_window", Section: SectionNetwork, Data: State, Risk: Safe},

	{Name: "dns.ready", Section: SectionDNS, Data: State, Risk: Safe},

	{Name: "qos.enabled", Section: SectionQoS, Data: Provider, Risk: Safe},
	{Name: "qos.down_kbit", Section: SectionQoS, Data: Provider, Risk: Safe},
	{Name: "qos.up_kbit", Section: SectionQoS, Data: Provider, Risk: Safe},
	{Name: "qos.measured_down_kbit", Section: SectionQoS, Data: State, Risk: Safe},
	{Name: "qos.measured_up_kbit", Section: SectionQoS, Data: State, Risk: Safe},
	{Name: "qos.measured_at", Section: SectionQoS, Data: State, Risk: Safe},
	{Name: "qos.measured_via", Section: SectionQoS, Data: State, Risk: Safe},
	{Name: "qos.direct_down_kbit", Section: SectionQoS, Data: State, Risk: Safe},
	{Name: "qos.direct_at", Section: SectionQoS, Data: State, Risk: Safe},

	{Name: "vpn.active_slug", Section: SectionVPN, Data: Office, Risk: Notable, RefersTo: OwnerVPNProfile,
		Why: "выбирает, через какой канал идёт трафик; профили — свои у каждого офиса"},
	{Name: "vpn.mode", Section: SectionVPN, Data: Policy, Risk: Dangerous,
		Why:   "решает, какой трафик идёт через канал, а какой мимо",
		Title: "Режим трафика офиса", Warn: "решает, что идёт через защищённый канал, а что — напрямую через провайдера"},
	{Name: "vpn.on_failure", Section: SectionVPN, Data: Policy, Risk: Dangerous,
		Why:   "значение direct выпускает трафик мимо канала при его падении",
		Title: "Поведение при падении канала", Warn: "может выпускать трафик офиса напрямую, мимо защищённого канала, пока канал лежит"},
	{Name: "vpn.mtu", Section: SectionVPN, Data: Provider, Risk: Safe},
	{Name: "vpn.dns_choice", Section: SectionVPN, Data: Policy, Risk: Dangerous,
		Why:   "решает, чей сервер разрешает имена для всего офиса",
		Title: "Сервер имён офиса", Warn: "решает, кто узнаёт, какие сайты открывают в офисе"},
	{Name: "vpn.probe_target.", Prefix: true, Owner: OwnerVPNProfile, Section: SectionVPN, Data: Office, Risk: Safe},

	{Name: "security.hidden_mode", Section: SectionSecurity, Data: Policy, Risk: Notable,
		Why: "меняет только ответ шлюза на ping, доступа не открывает"},
	{Name: "security.ipv6", Section: SectionSecurity, Data: Policy, Risk: Dangerous,
		Why:   "включает второй сетевой стек; по умолчанию выключен",
		Title: "IPv6", Warn: "открывает второй путь в интернет, который защищается отдельно"},
	{Name: "security.leak_seen", Section: SectionSecurity, Data: State, Risk: Safe},
	{Name: "security.first_start", Section: SectionSecurity, Data: State, Risk: Safe},
	{Name: "security.backup_exported", Section: SectionSecurity, Data: State, Risk: Safe},

	{Name: "retention.journal_days", Section: SectionRetention, Data: Policy, Risk: Safe},
	{Name: "retention.devices_forget_days", Section: SectionRetention, Data: Policy, Risk: Safe},
	{Name: "retention.trust_keep_days", Section: SectionRetention, Data: Policy, Risk: Safe},
	{Name: "retention.syslog_cap", Section: SectionRetention, Data: Policy, Risk: Safe},
	{Name: "retention.disk_budget_mb", Section: SectionRetention, Data: Machine, Risk: Safe,
		Why: "потолок зависит от размера и свободного места этого диска"},

	{Name: "diag.active_probes", Section: SectionDiag, Data: Policy, Risk: Notable,
		Why: "разрешает шлюзу самому опрашивать устройства офиса"},
	{Name: "diag.self_label", Section: SectionDiag, Data: Policy, Risk: Notable,
		Why: "разрешает сотрудникам предлагать подписи своих устройств"},
	{Name: "diag.window_max_hours", Section: SectionDiag, Data: Policy, Risk: Safe},
	{Name: "diag.window_until", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "diag.window_full", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "diag.fullcheck_until", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "diag.last_probe", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "path.underlay", Section: SectionDiag, Data: State, Risk: Safe},

	{Name: "metrics.master", Section: SectionMetrics, Data: Policy, Risk: Safe},
	{Name: "metrics.source.", Prefix: true, Owner: OwnerMetricsSource, Section: SectionMetrics, Data: Policy, Risk: Safe},

	{Name: "updates.seen_version", Section: SectionUpdates, Data: State, Risk: Safe},
	{Name: "updates.notice", Section: SectionUpdates, Data: State, Risk: Safe},

	{Name: "auth.max_users", Section: SectionAuth, Data: Policy, Risk: Notable,
		Why: "больше учётных записей — больше дверей в панель"},
	{Name: "auth.device_sliding_hours", Section: SectionAuth, Data: Policy, Risk: Notable,
		Why: "длиннее срок — дольше живёт украденный сеанс"},
	{Name: "auth.device_absolute_days", Section: SectionAuth, Data: Policy, Risk: Notable,
		Why: "длиннее срок — дольше живёт украденный сеанс"},
	{Name: "auth.quarantine_hours", Section: SectionAuth, Data: Policy, Risk: Notable,
		Why: "короче карантин — быстрее полные права у нового устройства"},
	{Name: "auth.code_ttl_minutes", Section: SectionAuth, Data: Policy, Risk: Notable,
		Why: "дольше живёт код подключения устройства"},
	{Name: "setup.code_hash", Section: SectionAuth, Data: State, Risk: Safe},
	{Name: "setup.code_expires_unix", Section: SectionAuth, Data: State, Risk: Safe},

	{Name: "setup.wan_card", Section: SectionNetwork, Data: State, Risk: Safe},
	{Name: "setup.lan_card", Section: SectionNetwork, Data: State, Risk: Safe},
	{Name: "setup.skipped", Section: SectionAuth, Data: State, Risk: Safe},
	{Name: "setup.finished", Section: SectionAuth, Data: State, Risk: Safe},
}

var Tables = []Table{
	{Name: "settings", Section: SectionNetwork, Data: Policy, Risk: Safe,
		Why: "классы — у каждого ключа в Keys"},
	{Name: "interfaces", Section: SectionNetwork, Data: Provider, Risk: Dangerous,
		Why:   "роли карт и подключение к провайдеру; имена и MAC карт — машина, сопоставляются заново",
		Title: "Сетевые карты и провайдер", Warn: "перепутанная роль карты отрежет офис от интернета или повернёт шлюз не той стороной"},
	{Name: "dhcp_reservations", Section: SectionDHCP, Data: Office, Risk: Notable,
		Why: "закрепления адресов за устройствами офиса"},
	{Name: "vpn_profiles", Section: SectionVPN, Data: Office, Risk: Dangerous, Owner: OwnerVPNProfile,
		Why:   "каналы офиса; ключи — у агента, в копию их кладёт он",
		Title: "Подключения VPN", Warn: "меняет, через чей сервер уходит трафик офиса"},
	{Name: "devices", Section: SectionDevices, Data: Office, Risk: Safe,
		Why: "переносятся только подписи, данные администратором"},
	{Name: "users", Section: SectionAuth, Data: Machine, Risk: Safe,
		Why: "учётные записи не переносятся — на новом шлюзе заводятся заново"},
	{Name: "trusted_devices", Section: SectionAuth, Data: Machine, Risk: Safe,
		Why: "доверие браузеров не переносится"},
	{Name: "enroll_codes", Section: SectionAuth, Data: State, Risk: Safe},
	{Name: "auth_events", Section: SectionAuth, Data: State, Risk: Safe},
	{Name: "boots", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "vpn_checks", Section: SectionVPN, Data: State, Risk: Safe},
	{Name: "jobs", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "failed_jobs", Section: SectionDiag, Data: State, Risk: Safe},
	{Name: "migrations", Section: SectionDiag, Data: State, Risk: Safe},
}

func Lookup(key string) (Key, bool) {
	for _, k := range Keys {
		if !k.Prefix && k.Name == key {
			return k, true
		}
	}
	for _, k := range Keys {
		if k.Prefix && strings.HasPrefix(key, k.Name) && len(key) > len(k.Name) {
			return k, true
		}
	}
	return Key{}, false
}

func Validate(keys []Key, tables []Table) []error {
	var errs []error
	seen := map[string]bool{}
	check := func(what, name string, section Section, data Data, risk Risk, why, title, warn string) {
		switch {
		case name == "":
			errs = append(errs, fmt.Errorf("%s без имени", what))
			return
		case seen[what+name]:
			errs = append(errs, fmt.Errorf("%s %q объявлен дважды", what, name))
		}
		seen[what+name] = true
		if section == "" || data == 0 || risk == 0 {
			errs = append(errs, fmt.Errorf("%s %q: не задан раздел, класс данных или класс риска", what, name))
		}
		if (risk == Dangerous || data == Machine) && strings.TrimSpace(why) == "" {
			errs = append(errs, fmt.Errorf("%s %q: для опасной или привязанной к машине настройки нужна причина", what, name))
		}
		if risk == Dangerous && (strings.TrimSpace(title) == "" || strings.TrimSpace(warn) == "") {
			errs = append(errs, fmt.Errorf("%s %q: опасной настройке нужны название и предупреждение для окна импорта", what, name))
		}
		if !data.InCopy() && data != 0 && risk != Safe {
			errs = append(errs, fmt.Errorf("%s %q: непереносимые данные не бывают заметными или опасными — класс данных задан неверно", what, name))
		}
	}
	for _, k := range keys {
		check("ключ", k.Name, k.Section, k.Data, k.Risk, k.Why, k.Title, k.Warn)
		if k.Data == Secret {
			errs = append(errs, fmt.Errorf("ключ %q: секретам не место в базе панели — они только у агента", k.Name))
		}
		if k.Prefix && !strings.HasSuffix(k.Name, ".") {
			errs = append(errs, fmt.Errorf("ключ %q: начало ключа обязано кончаться точкой", k.Name))
		}
		switch {
		case k.Prefix && k.Owner == "":
			errs = append(errs, fmt.Errorf("ключ %q: у переменного хвоста нет владельца — после удаления объекта ключ останется сиротой", k.Name))
		case !k.Prefix && k.Owner != "":
			errs = append(errs, fmt.Errorf("ключ %q: владелец хвоста у ключа без хвоста", k.Name))
		case k.Prefix && k.RefersTo != "":
			errs = append(errs, fmt.Errorf("ключ %q: ссылка на объект — только у ключа без хвоста", k.Name))
		}
		for _, o := range []Owner{k.Owner, k.RefersTo} {
			if o != "" && !slices.Contains(owners, o) {
				errs = append(errs, fmt.Errorf("ключ %q: неизвестный владелец %q", k.Name, o))
			}
		}
	}
	tableOf := map[Owner]string{}
	for _, t := range tables {
		check("таблица", t.Name, t.Section, t.Data, t.Risk, t.Why, t.Title, t.Warn)
		if t.Owner != "" {
			if !slices.Contains(owners, t.Owner) {
				errs = append(errs, fmt.Errorf("таблица %q: неизвестный владелец %q", t.Name, t.Owner))
			}
			if prev, dup := tableOf[t.Owner]; dup {
				errs = append(errs, fmt.Errorf("у владельца %q две таблицы: %q и %q", t.Owner, prev, t.Name))
			}
			tableOf[t.Owner] = t.Name
		}
		if t.Data == Secret {
			errs = append(errs, fmt.Errorf("таблица %q: секретам не место в базе панели — они только у агента", t.Name))
		}
	}
	return errs
}

func Owned(keys []Key, owner Owner, id string) (drop, clear []string) {
	if id == "" {
		return nil, nil
	}
	for _, k := range keys {
		if k.Prefix && k.Owner == owner {
			drop = append(drop, k.Name+id)
		}
		if k.RefersTo == owner {
			clear = append(clear, k.Name)
		}
	}
	return drop, clear
}

func OwnerTable(tables []Table, owner Owner) (Table, bool) {
	for _, t := range tables {
		if owner != "" && t.Owner == owner {
			return t, true
		}
	}
	return Table{}, false
}

var ErrUndeclared = errors.New("ключ не объявлен в реестре настроек")
