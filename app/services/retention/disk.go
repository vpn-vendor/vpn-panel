package retention

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskstat"
)

const (
	GiB = 1 << 30
	MiB = 1 << 20

	ReservePercent = 15
	ReserveMin     = 2 * GiB
	CeilingPercent = 10
	CeilingHard    = 10 * GiB
	BudgetDefault  = 2 * GiB
	BudgetFloor    = 256 * MiB

	RaiseHysteresis = 0.10

	WarnPercent     = 10
	WarnMin         = 1 * GiB
	CriticalPercent = 5
	CriticalMin     = 512 * MiB

	SyslogCap = 256 * MiB

	DiskCheckEvery = 10 * time.Second
)

const (
	SettingDiskBudgetMB = "retention.disk_budget_mb"
	SettingSyslogCap    = "retention.syslog_cap"
)

const (
	panelDataDir = "/var/lib/vpn-panel"
	logDir       = "/var/log"
)

var SyslogFiles = []string{"syslog", "kern.log", "auth.log", "user.log", "mail.log", "cron.log"}

func Budget(total, availUnpriv, ours, admin uint64) (ceiling, budget uint64, starved bool) {
	reserve := total * ReservePercent / 100
	if reserve < ReserveMin {
		reserve = ReserveMin
	}
	ceiling = total * CeilingPercent / 100
	if usable := availUnpriv + ours; usable > reserve {
		if usable-reserve < ceiling {
			ceiling = usable - reserve
		}
	} else {
		ceiling = 0
	}
	if ceiling > CeilingHard {
		ceiling = CeilingHard
	}
	if admin == 0 {
		admin = BudgetDefault
	}
	budget = admin
	if budget > ceiling {
		budget = ceiling
	}
	if budget < BudgetFloor {
		return ceiling, BudgetFloor, true
	}
	return ceiling, budget, false
}

func Pressure(total, availUnpriv uint64) int {
	warn := total * WarnPercent / 100
	if warn < WarnMin {
		warn = WarnMin
	}
	crit := total * CriticalPercent / 100
	if crit < CriticalMin {
		crit = CriticalMin
	}
	switch {
	case availUnpriv < crit:
		return 2
	case availUnpriv < warn:
		return 1
	}
	return 0
}

type LogFile struct {
	Name    string
	Live    uint64
	Rotated uint64
}

func (f LogFile) Total() uint64 { return f.Live + f.Rotated }

func LogSizes() []LogFile {
	out := make([]LogFile, 0, len(SyslogFiles))
	for _, name := range SyslogFiles {
		f := LogFile{Name: name}
		if st, err := os.Stat(filepath.Join(logDir, name)); err == nil {
			f.Live = uint64(st.Size()) //nolint:gosec
		}
		matches, _ := filepath.Glob(filepath.Join(logDir, name+".*"))
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil {
				f.Rotated += uint64(st.Size()) //nolint:gosec
			}
		}
		out = append(out, f)
	}
	return out
}

func DataDir() string { return panelDataDir }

func OurData() uint64 {
	var total uint64
	matches, _ := filepath.Glob(filepath.Join(panelDataDir, "*"))
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && !st.IsDir() {
			total += uint64(st.Size()) //nolint:gosec
		}
	}
	return total
}

type DiskState struct {
	Total       uint64
	AvailUnpriv uint64
	Ours        uint64
	Ceiling     uint64
	Budget      uint64
	AdminBudget uint64
	Starved     bool
	Pressure    int
	Logs        []LogFile
	SyslogCap   bool
	Checked     time.Time
	LastTrim    time.Time
	Error       string
}

func (d DiskState) OverBudget() bool { return d.Ours > d.Budget }

func (d DiskState) LogsTotal() uint64 {
	var t uint64
	for _, f := range d.Logs {
		t += f.Total()
	}
	return t
}

var (
	diskMu        sync.Mutex
	diskLast      DiskState
	ceilingSeen   uint64
	ceilingActing uint64
	pressureSaid  int

	trimEpisode int
)

func CurrentDisk() DiskState {
	diskMu.Lock()
	defer diskMu.Unlock()
	return diskLast
}

func DiskCheck(now time.Time, trim func(files []string) error) DiskState {
	st := DiskState{Checked: now, Logs: LogSizes(), Ours: OurData(),
		SyslogCap: settingString(SettingSyslogCap) == "1"}
	space, err := diskstat.Usage(panelDataDir)
	if err != nil {

		diskMu.Lock()
		prev := diskLast
		diskMu.Unlock()
		if prev.Checked.IsZero() {
			st.Budget, st.Starved = BudgetFloor, true
		} else {
			st.Total, st.AvailUnpriv, st.Ceiling, st.Budget, st.Starved = prev.Total, prev.AvailUnpriv, prev.Ceiling, prev.Budget, prev.Starved
		}
		st.Error = "не удалось узнать свободное место"
	} else {
		st.Total, st.AvailUnpriv = space.Total, space.AvailUnpriv
		st.AdminBudget = uint64(settingInt(SettingDiskBudgetMB)) * MiB //nolint:gosec
		ceiling, _, _ := Budget(st.Total, st.AvailUnpriv, st.Ours, st.AdminBudget)
		st.Ceiling = applyHysteresis(ceiling)
		_, st.Budget, st.Starved = Budget(st.Total, st.AvailUnpriv, st.Ours, st.AdminBudget)
		if st.Ceiling < st.Budget {
			st.Budget = st.Ceiling
			if st.Budget < BudgetFloor {
				st.Budget, st.Starved = BudgetFloor, true
			}
		}
		st.Pressure = Pressure(st.Total, st.AvailUnpriv)
	}

	diskMu.Lock()
	st.LastTrim = diskLast.LastTrim
	diskLast = st
	said := pressureSaid
	pressureSaid = st.Pressure
	diskMu.Unlock()

	if st.Pressure != said {
		switch st.Pressure {
		case 2:
			securitylog.Record(models.AuthEvent{Event: "disk_critical", IP: "", OccurredAt: now,
				Details: "свободно " + human(st.AvailUnpriv) + " из " + human(st.Total)})
		case 1:
			securitylog.Record(models.AuthEvent{Event: "disk_low", IP: "", OccurredAt: now,
				Details: "свободно " + human(st.AvailUnpriv) + " из " + human(st.Total)})
		}
	}
	if trim == nil {
		return st
	}

	var targets []string
	for _, f := range st.Logs {
		if (st.Pressure == 2 && f.Total() > 64*MiB) || (st.SyslogCap && f.Live > SyslogCap) {
			targets = append(targets, f.Name)
		}
	}
	if len(targets) == 0 {
		diskMu.Lock()
		count := trimEpisode
		trimEpisode = 0
		diskMu.Unlock()
		if count > 1 {
			securitylog.Record(models.AuthEvent{Event: "syslog_trimmed", OccurredAt: now,
				Details: "серия закончилась: всего обрезок " + strconv.Itoa(count)})
		}
		return st
	}
	if err := trim(targets); err != nil {
		log.Printf("сторож диска: обрезка журналов не удалась: %v", err)
		return st
	}
	diskMu.Lock()
	trimEpisode++
	first := trimEpisode == 1
	diskLast.LastTrim = now
	diskMu.Unlock()
	if first {
		reason := "предел размера журнала"
		if st.Pressure == 2 {
			reason = "на диске кончается место"
		}
		securitylog.Record(models.AuthEvent{Event: "syslog_trimmed", OccurredAt: now,
			Details: reason + ": " + joinNames(targets)})
	}
	return st
}

func applyHysteresis(ceiling uint64) uint64 {
	diskMu.Lock()
	defer diskMu.Unlock()
	switch {
	case ceilingActing == 0 || ceiling <= ceilingActing:
		ceilingActing = ceiling
	case float64(ceiling) > float64(ceilingActing)*(1+RaiseHysteresis) &&
		float64(ceilingSeen) > float64(ceilingActing)*(1+RaiseHysteresis):
		ceilingActing = ceiling
	}
	ceilingSeen = ceiling
	return ceilingActing
}

func DiskNotice() (level, text string) {
	st := CurrentDisk()
	switch {
	case st.Pressure == 2:
		return "error", "На диске сервера почти не осталось места (свободно " + human(st.AvailUnpriv) +
			"). Панель обрезает разросшиеся системные журналы сама; если место не появляется — освободите его или обратитесь в поддержку. Пока места нет, настройки могут не сохраняться."
	case st.Pressure == 1:
		return "warn", "На диске сервера мало места (свободно " + human(st.AvailUnpriv) +
			"). Проверьте раздел «Диск и системные журналы» на странице «Защита»."
	case st.Starved:
		return "warn", "Диск сервера слишком мал для обычного хранения данных панели: история хранится по минимуму. Освободите место на диске."
	}
	return "", ""
}

func SaveDiskBudget(mb int) error {
	st := CurrentDisk()
	ceilingMB := int(st.Ceiling / MiB) //nolint:gosec
	floorMB := BudgetFloor / MiB
	if mb < floorMB || (ceilingMB > 0 && mb > ceilingMB) {
		return &BudgetError{FloorMB: floorMB, CeilingMB: ceilingMB}
	}
	return setSetting(SettingDiskBudgetMB, strconv.Itoa(mb))
}

type BudgetError struct{ FloorMB, CeilingMB int }

func (e *BudgetError) Error() string {
	return "бюджет диска — от " + strconv.Itoa(e.FloorMB) + " до " + strconv.Itoa(e.CeilingMB) + " МБ (потолок зависит от свободного места)"
}

func settingString(key string) string { return settings.Get(key) }

func human(b uint64) string {
	switch {
	case b >= GiB:
		return strconv.FormatFloat(float64(b)/GiB, 'f', 1, 64) + " ГБ"
	case b >= MiB:
		return strconv.FormatUint(b/MiB, 10) + " МБ"
	}
	return strconv.FormatUint(b/1024, 10) + " КБ"
}

func Human(b uint64) string { return human(b) }

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
