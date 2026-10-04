package diagnose

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/diagfacts"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

const (
	LevelOK    = "ok"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

const (
	LossThresholdPercent = 1
	JitterThresholdMs    = 10.0
)

type Lease struct {
	IP       string
	MAC      string
	Hostname string
	Until    time.Time
}

type LAN struct {
	Name     string
	CIDR     string
	PoolFrom net.IP
	PoolTo   net.IP
}

func inPool(ipStr string, lans []LAN) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	for _, l := range lans {
		from, to := l.PoolFrom.To4(), l.PoolTo.To4()
		if from == nil || to == nil {
			continue
		}
		if bytesCompare(ip, from) >= 0 && bytesCompare(ip, to) <= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b net.IP) int {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

type Input struct {
	Now        time.Time
	LANs       []LAN
	Leases     []Lease
	Neighbours []diagfacts.Neighbour
	Sets       map[string][]diagfacts.SetEntry
	Links      []diagfacts.LinkStats
	Probe      map[string]diagfacts.ProbeResult
	ProbedAt   time.Time
	Vendor     func(mac string) string
	Randomized func(mac string) bool

	Exclude map[string]bool
}

type Diagnosis struct {
	Code       string
	Level      string
	Title      string
	Advice     string
	Confidence string
}

type Device struct {
	MAC       string
	IP        string
	Hostname  string
	Vendor    string
	RandomMAC bool
	Managed   bool
	Online    bool
	Level     string
	Diagnoses []Diagnosis
	Probe     *diagfacts.ProbeResult
}

type Report struct {
	Devices []Device
	Network []Diagnosis
	Level   string
}

func Run(in Input) Report {
	byMAC := map[string]*Device{}
	order := []string{}
	get := func(mac string) *Device {
		mac = strings.ToLower(mac)
		if d, ok := byMAC[mac]; ok {
			return d
		}
		d := &Device{MAC: mac, Level: LevelOK}
		byMAC[mac] = d
		order = append(order, mac)
		return d
	}
	vendor := in.Vendor
	if vendor == nil {
		vendor = func(string) string { return "" }
	}
	randomized := in.Randomized
	if randomized == nil {
		randomized = func(string) bool { return false }
	}

	hostMACs := map[string]map[string]bool{}
	for _, l := range in.Leases {
		if l.MAC == "" || in.Exclude[l.IP] {
			continue
		}
		d := get(l.MAC)
		d.Managed = true
		if d.IP == "" {
			d.IP = l.IP
		}
		if h := strings.TrimSuffix(l.Hostname, "."); h != "" {
			d.Hostname = h
			key := strings.ToLower(h)
			if hostMACs[key] == nil {
				hostMACs[key] = map[string]bool{}
			}
			hostMACs[key][strings.ToLower(l.MAC)] = true
		}
	}

	for _, n := range in.Neighbours {
		if n.MAC == "" || in.Exclude[n.IP] || !inLANs(n.IP, in.LANs) {
			continue
		}
		d := get(n.MAC)
		d.IP = n.IP
		if online(n.State) {
			d.Online = true
		}
	}

	for _, mac := range order {
		d := byMAC[mac]
		d.Vendor = vendor(mac)
		d.RandomMAC = randomized(mac)
		if !d.Managed {
			if inPool(d.IP, in.LANs) {

				d.add(Diagnosis{Code: "unknown_lease", Level: LevelInfo, Confidence: "средняя",
					Title:  "Адрес из диапазона автоматической выдачи, но текущий сервер его не выдавал — устройство держит старую аренду (например, после переустановки сервера).",
					Advice: "Ничего делать не нужно: адрес обновится при следующем продлении. Чтобы сразу — переподключите сетевой кабель устройства."})
			} else {
				d.add(Diagnosis{Code: "static_ip", Level: LevelWarn, Confidence: "высокая",
					Title:  "Адрес задан на устройстве вручную — панель не управляет его сетевыми параметрами.",
					Advice: "Переключите получение адреса и DNS на автоматическое; для устройств, которым нужен постоянный адрес, используйте закрепление на странице «Выдача адресов»."})
			}
		}
		if d.RandomMAC {
			d.add(Diagnosis{Code: "random_mac", Level: LevelInfo, Confidence: "низкая",
				Title:  "Аппаратный адрес случайный (обычно Wi-Fi со случайным адресом) — устройство могло уже сменить адрес.",
				Advice: "Для стабильного опознания отключите случайные аппаратные адреса в настройках Wi-Fi этого устройства."})
		}
		if h := strings.ToLower(d.Hostname); h != "" && len(hostMACs[h]) > 1 {
			d.add(Diagnosis{Code: "mac_flapping", Level: LevelWarn, Confidence: "средняя",
				Title:  "Одно имя компьютера получало адреса с разных аппаратных адресов — устройство меняет аппаратный адрес или несколько устройств названы одинаково.",
				Advice: "Проверьте настройки сетевых адаптеров устройства; переименуйте устройства с одинаковыми именами."})
		}
		if e, ok := findEntry(in.Sets[nftgen.SetForeignDNS], d.IP); ok {
			d.add(Diagnosis{Code: "foreign_dns", Level: LevelError, Confidence: "высокая",
				Title:  fmt.Sprintf("На устройстве указан посторонний DNS: %d запросов ушли мимо сервера имён шлюза (последний — %s) — звонки и имена могут идти в обход защиты.", e.Packets, ageText(e)),
				Advice: "Исправьте на устройстве: настройки сети → DNS → получать автоматически. Для кастомных сборок Windows проверьте, не прописан ли 8.8.8.8/1.1.1.1 вручную."})
		}
		if e, ok := findEntry(in.Sets[nftgen.SetIPv6Tunnel], d.IP); ok {
			d.add(Diagnosis{Code: "ipv6_tunnel", Level: LevelError, Confidence: "высокая",
				Title:  fmt.Sprintf("Устройство пыталось поднять туннель IPv6 поверх IPv4 (Teredo/6to4): %d попыток, последняя — %s. Шлюз их блокирует — это обход защищённого канала.", e.Packets, ageText(e)),
				Advice: "На устройстве выключите Teredo и службу IP Helper (iphlpsvc) либо оставьте как есть — шлюз не пропускает такие попытки."})
		}
		if _, ok := findEntry(in.Sets[nftgen.SetOwnVPN], d.IP); ok {
			d.add(Diagnosis{Code: "own_vpn", Level: LevelError, Confidence: "средняя",
				Title:  "Похоже, на устройстве работает собственный VPN-клиент: трафик идёт на порты VPN напрямую. Телефония через личный VPN поверх шлюза — вне гарантий качества и анонимности.",
				Advice: "Отключите VPN-клиент на устройстве: защищённый канал уже обеспечивает шлюз."})
		}
		if e, ok := findEntry(in.Sets[nftgen.SetUpdatesP2P], d.IP); ok {
			d.add(Diagnosis{Code: "updates_p2p", Level: LevelWarn, Confidence: "средняя",
				Title:  fmt.Sprintf("Устройство раздаёт обновления Windows другим компьютерам через интернет (%d соединений) — это занимает канал офиса.", e.Packets),
				Advice: "В Windows: Параметры → Обновление → Оптимизация доставки → выключить «Разрешить загрузки с других компьютеров» или оставить только для локальной сети."})
		}
		if p, ok := in.Probe[d.IP]; ok {
			pr := p
			d.Probe = &pr
			switch {
			case p.Sent > 0 && p.Received == 0:
				d.add(Diagnosis{Code: "probe_silent", Level: LevelWarn, Confidence: "средняя",
					Title:  "Во время проверки устройство не отвечало (выключено, отключён кабель или спит).",
					Advice: "Если устройство было включено — проверьте кабель и порт коммутатора и повторите проверку."})
			case p.LossPercent() >= LossThresholdPercent || p.JitterMs >= JitterThresholdMs:
				d.add(Diagnosis{Code: "lan_quality", Level: LevelError, Confidence: "высокая",
					Title:  fmt.Sprintf("Проверка до устройства показала потери %d %% и разброс задержки %.1f мс ещё внутри офиса — звонки будут страдать до выхода в интернет.", p.LossPercent(), p.JitterMs),
					Advice: "Проверьте кабель и порт коммутатора на пути к устройству; для Wi-Fi — уровень сигнала и режим энергосбережения адаптера."})
			}
		}
		d.Level = maxLevel(d.Diagnoses)
	}

	report := Report{Level: LevelOK}
	for _, ls := range in.Links {
		if ls.SpeedMbit > 0 && ls.SpeedMbit < 1000 {
			report.Network = append(report.Network, Diagnosis{Code: "link_speed", Level: LevelWarn, Confidence: "высокая",
				Title:  fmt.Sprintf("Карта локальной сети «%s» работает на %d Мбит/с.", ls.Name, ls.SpeedMbit),
				Advice: "Скорее всего, узкое место — кабель (4-жильный даёт максимум 100 Мбит/с) или коммутатор на 100 Мбит/с. Замените кабель на 8-жильный и проверьте порт."})
		}
		if ls.Duplex == "half" {
			report.Network = append(report.Network, Diagnosis{Code: "link_half_duplex", Level: LevelError, Confidence: "высокая",
				Title:  fmt.Sprintf("Карта «%s» работает в полудуплексе — данные идут по очереди, с коллизиями.", ls.Name),
				Advice: "Причина — несогласованность с портом коммутатора или повреждённый кабель. Замените кабель; на управляемом коммутаторе включите автосогласование."})
		}
		if ls.RxCRC > 0 || ls.RxErrors > 0 || ls.Collisions > 0 {
			report.Network = append(report.Network, Diagnosis{Code: "link_errors", Level: LevelError, Confidence: "высокая",
				Title:  fmt.Sprintf("На карте «%s» есть ошибки приёма (%d) и коллизии (%d) — признак плохого кабеля или порта.", ls.Name, ls.RxErrors+ls.RxCRC, ls.Collisions),
				Advice: "Замените кабель между сервером и коммутатором и проверьте порт коммутатора."})
		}
	}
	report.Level = maxLevel(report.Network)

	for _, mac := range order {
		report.Devices = append(report.Devices, *byMAC[mac])
		if levelRank(byMAC[mac].Level) > levelRank(report.Level) {
			report.Level = byMAC[mac].Level
		}
	}
	sort.SliceStable(report.Devices, func(i, j int) bool {
		if ri, rj := levelRank(report.Devices[i].Level), levelRank(report.Devices[j].Level); ri != rj {
			return ri > rj
		}
		return ipLess(report.Devices[i].IP, report.Devices[j].IP)
	})
	return report
}

func (d *Device) add(x Diagnosis) { d.Diagnoses = append(d.Diagnoses, x) }

func ageText(e diagfacts.SetEntry) string {
	age := nftgen.DiagSetTimeoutSec - e.Expires
	switch {
	case e.Expires <= 0 || age < 0:
		return ""
	case age < 120:
		return "только что"
	case age < 7200:
		return fmt.Sprintf("%d мин назад", age/60)
	default:
		return fmt.Sprintf("%d ч назад", age/3600)
	}
}

func findEntry(entries []diagfacts.SetEntry, ip string) (diagfacts.SetEntry, bool) {
	for _, e := range entries {
		if e.IP == ip && e.Packets > 0 {
			return e, true
		}
	}
	return diagfacts.SetEntry{}, false
}

func inLANs(ipStr string, lans []LAN) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, l := range lans {
		if _, n, err := net.ParseCIDR(l.CIDR); err == nil && n.Contains(ip) {
			return true
		}
	}
	return len(lans) == 0
}

func levelRank(l string) int {
	switch l {
	case LevelError:
		return 3
	case LevelWarn:
		return 2
	case LevelInfo:
		return 1
	}
	return 0
}

func maxLevel(ds []Diagnosis) string {
	level := LevelOK
	for _, d := range ds {
		if levelRank(d.Level) > levelRank(level) {
			level = d.Level
		}
	}
	return level
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ia[i] != ib[i] {
			return ia[i] < ib[i]
		}
	}
	return false
}

func online(state string) bool {
	switch state {
	case "REACHABLE", "DELAY", "PROBE", "PERMANENT":
		return true
	}
	return false
}

func OnlineNow(in Input) int {
	seen := map[string]bool{}
	for _, n := range in.Neighbours {
		if n.MAC == "" || in.Exclude[n.IP] || !inLANs(n.IP, in.LANs) || !online(n.State) {
			continue
		}
		seen[n.MAC] = true
	}
	return len(seen)
}
