package health

type Class int

const (
	UpdateFault Class = iota

	External
)

type Severity int

const (
	Catastrophic Severity = iota

	Soft
)

type Check struct {
	Name     string
	Class    Class
	Severity Severity
	Why      string
}

var registry = []Check{
	{Name: "service-crash-loop", Class: UpdateFault, Severity: Catastrophic,
		Why: "служба панели не удерживается запущенной — падает по кругу"},
	{Name: "agent-unreachable", Class: UpdateFault, Severity: Catastrophic,
		Why: "системная служба не отвечает после обновления"},
	{Name: "db-corrupt", Class: UpdateFault, Severity: Catastrophic,
		Why: "база настроек повреждена после миграции"},
	{Name: "intent-broken", Class: UpdateFault, Severity: Catastrophic,
		Why: "намерение защищённого канала не читается"},
	{Name: "killswitch-down", Class: UpdateFault, Severity: Catastrophic,
		Why: "защита от утечки трафика мимо канала не действует"},
	{Name: "service-restarted", Class: UpdateFault, Severity: Soft,
		Why: "служба панели перезапускалась после обновления — версия шаткая"},
	{Name: "panel-unserved", Class: UpdateFault, Severity: Soft,
		Why: "панель не открывает свои страницы"},
	{Name: "data-stuck", Class: UpdateFault, Severity: Soft,
		Why: "данные не идут через канал при живом рукопожатии"},
	{Name: "panel-port-taken", Class: External, Severity: Soft,
		Why: "порт панели заняла чужая программа"},
	{Name: "channel-offline", Class: External, Severity: Soft,
		Why: "канал не поднимается — похоже на сторону сервера или провайдера"},
}

func byName(name string) (Check, bool) {
	for _, c := range registry {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func Registry() []Check {
	out := make([]Check, len(registry))
	copy(out, registry)
	return out
}

type Reading struct {
	Name        string
	BadNow      bool
	BadOnAnchor bool
}

type Decision int

const (
	Healthy Decision = iota

	AwaitDecision

	Rollback
)

type Verdict struct {
	Decision Decision
	Reasons  []string
}

func attributable(c Check, r Reading) bool {
	return c.Class == UpdateFault && r.BadNow && !r.BadOnAnchor
}

func Judge(readings []Reading) Verdict {
	v := Verdict{Decision: Healthy}
	for _, r := range readings {
		c, ok := byName(r.Name)
		if !ok || !attributable(c, r) {
			continue
		}
		v.Reasons = append(v.Reasons, c.Why)
		switch c.Severity {
		case Catastrophic:
			v.Decision = Rollback
		case Soft:
			if v.Decision != Rollback {
				v.Decision = AwaitDecision
			}
		}
	}
	return v
}
