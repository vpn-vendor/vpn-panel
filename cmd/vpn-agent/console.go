package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/console"
	"github.com/vpn-vendor/vpn-panel-core/internal/help"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndiag"
)

const (
	codePanelBusy = 2301
)

const (
	panelUnit = "vpn-panel.service"
	agentUnit = "vpn-agent.service"
	panelEnv  = "/etc/vpn-panel/panel.env"

	panelServer = "/usr/libexec/vpn-panel/vpn-panel"

	consoleIdle = 10 * time.Minute

	restartWait = 30 * time.Second
)

type panelApplier struct {
	limiter *ratelimit.Limiter
}

func newPanelApplier() *panelApplier {
	return &panelApplier{limiter: ratelimit.New(3, 1, time.Minute)}
}

func (p *panelApplier) panelRestart(json.RawMessage) (any, *agentrpc.ErrorObject) {
	if !p.limiter.Allow("restart") {
		return nil, agentrpc.Busy(codePanelBusy, "панель перезапускается слишком часто — подождите", p.limiter.RetryIn("restart"))
	}
	if err := systemctl("restart", panelUnit); err != nil {
		return nil, detailErr("панель не перезапустилась", err.Error(), true)
	}
	return map[string]any{"restarted": true}, nil
}

func systemctl(args ...string) error {
	bin, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return err
	}
	out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func unitActive(unit string) bool { return systemctl("is-active", "--quiet", unit) == nil }

type channelView struct {
	Mode              string `json:"mode"`
	IntentBroken      bool   `json:"intent_broken"`
	Present           bool   `json:"present"`
	Online            bool   `json:"online"`
	Degraded          bool   `json:"degraded"`
	RetryPaused       bool   `json:"retry_paused"`
	SelfHealing       bool   `json:"self_healing"`
	FailReason        string `json:"fail_reason"`
	FailCount         int    `json:"fail_count"`
	ProcState         string `json:"proc_state"`
	HandshakeS        int64  `json:"handshake_age_sec"`
	DataDead          bool   `json:"data_dead"`
	DataSuspect       bool   `json:"data_suspect"`
	DataRestarts      int64  `json:"data_restarts"`
	DataRestartBudget int64  `json:"data_restart_budget"`
}

func (v channelView) facts() vpndiag.Facts {
	return vpndiag.Facts{
		ModeBlack: v.Mode == modeBlack, Present: v.Present, Online: v.Online, Degraded: v.Degraded,
		HandshakeEver: v.HandshakeS > 0 || v.Online, HandshakeAgeSec: v.HandshakeS,
		ProcState: v.ProcState, FailReason: v.FailReason, FailCount: v.FailCount,
		RetryPaused: v.RetryPaused, SelfHealing: v.SelfHealing,
		DataStuck:   v.DataDead && v.DataRestartBudget > 0 && v.DataRestarts >= v.DataRestartBudget,
		DataSuspect: v.DataSuspect,
	}
}

type gatewayFacts struct {
	ServiceAnswers bool
	Channel        channelView
	Network        netstatus.Status
	PanelActive    bool
	PanelAnswers   bool
}

var levelOf = map[vpndiag.Level]console.Level{
	vpndiag.LevelOK: console.OK, vpndiag.LevelInfo: console.OK,
	vpndiag.LevelWarn: console.Warn, vpndiag.LevelError: console.Bad,
}

var badgeWord = map[console.Level]string{
	console.OK: "работает", console.Warn: "есть замечание", console.Bad: "не работает",
	console.Unknown: "не удалось проверить", console.Off: "выключен",
}

func gatewayStatus(f gatewayFacts, restart int) console.Status {
	internet := console.Line{Key: string(help.CheckInternet), Label: "Интернет от провайдера", LabelEN: "Internet", Level: console.Unknown}
	channel := console.Line{Key: string(help.CheckChannel), Label: "Защищённый канал", LabelEN: "Secure channel", Level: console.Unknown}
	panel := console.Line{Key: string(help.CheckPanel), Label: "Панель управления", LabelEN: "Panel", Level: console.OK}
	st := console.Status{Level: console.OK, Badge: "всё работает", Headline: "Делать ничего не нужно"}
	worse := func(level console.Level, headline string, advice ...string) {
		if level > st.Level {
			st.Level, st.Headline, st.Advice = level, headline, advice
		}
	}

	switch {
	case !f.PanelActive:
		panel.Level, panel.Text = console.Bad, "остановлена"
	case !f.PanelAnswers:
		panel.Level, panel.Text = console.Bad, "не отвечает"
	}
	if panel.Level == console.Bad {
		worse(console.Bad, "Панель управления не открывается", "Что делать: нажмите "+fmt.Sprint(restart)+" — перезапуск панели. Интернет в офисе при этом не прервётся.")
		st.Suggest = restart
	}

	if !f.ServiceAnswers {
		worse(console.Bad, "Служба шлюза не отвечает — состояние узнать не удалось",
			"Что делать: нажмите "+fmt.Sprint(restart)+" — перезапуск служб панели.")
		st.Suggest = restart
	} else {
		internet.Level = console.Bad
		for _, route := range f.Network.DefaultRoutes {
			for _, card := range f.Network.Interfaces {
				if card.Name == route.Dev && card.State != "DOWN" && len(card.Addresses) > 0 {
					internet.Level = console.OK
				}
			}
		}
		if internet.Level == console.Bad {
			worse(console.Bad, "Нет подключения к провайдеру", "Что делать: проверьте кабель провайдера и его оборудование.")
		}

		finding, protected := vpndiag.State(f.Channel.facts())
		switch {
		case f.Channel.IntentBroken:
			channel.Level, channel.Note = console.Bad, "настройки канала не читаются"
			worse(console.Bad, "Офис закрыт от интернета намеренно: настройки канала не читаются",
				"Что делать: откройте панель, раздел VPN, и нажмите «Применить».")
		case !protected:
			channel.Level = console.Off
			if st.Level == console.OK {
				st.Headline = "Офис выходит в интернет напрямую, без защищённого канала"
			}
		default:
			channel.Level = levelOf[finding.Level]
			if channel.Level != console.OK {
				channel.Note = finding.Title
				worse(channel.Level, finding.Title, "Что делать: "+finding.Action)
			} else if st.Level == console.OK {
				st.Headline = "Офис в сети и выходит через защищённый канал"
			}
		}
	}

	for _, line := range []*console.Line{&internet, &channel, &panel} {
		if line.Text == "" {
			line.Text = badgeWord[line.Level]
		}
	}
	if internet.Level == console.OK {
		internet.Text = "подключён"
	}
	if channel.Level == console.OK {
		channel.Text = "подключён"
	}
	switch st.Level {
	case console.Warn:
		st.Badge = "есть замечание"
	case console.Bad:
		st.Badge = "нужно внимание"
	}
	st.Lines = []console.Line{internet, channel, panel}
	return st
}

type gateway struct {
	client *agentrpc.Client
}

func (g *gateway) call(method string, into any) bool {
	resp, err := g.client.Call(method, map[string]any{})
	if err != nil || resp.Error != nil {
		return false
	}
	return into == nil || json.Unmarshal(resp.Result, into) == nil
}

func (g *gateway) facts() gatewayFacts {
	f := gatewayFacts{PanelActive: unitActive(panelUnit)}
	f.ServiceAnswers = g.call("vpn.status", &f.Channel) && g.call("network.status", &f.Network)
	f.PanelAnswers = f.PanelActive && panelAnswers()
	return f
}

func panelAnswers() bool {
	port := ""
	data, err := os.ReadFile(panelEnv)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "APP_TLS_PORT="); ok {
			port = strings.TrimSpace(v)
		}
	}
	if port == "" {
		return false
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func tell(cmd *exec.Cmd) console.Result {
	out, err := cmd.CombinedOutput()
	res := console.Result{Level: console.OK, Lines: strings.Split(strings.TrimRight(string(out), "\n"), "\n")}
	if err != nil {
		res.Level = console.Bad
		if strings.TrimSpace(string(out)) == "" {
			res.Lines = []string{"Не получилось. Повторите; если повторяется — соберите сведения для поддержки."}
		}
	}
	return res
}

func packaged(name string, args ...string) *exec.Cmd {
	return exec.Command("/usr/sbin/"+name, args...) //nolint:gosec
}

func panelCommand(args ...string) *exec.Cmd {
	script := "set -a; . " + panelEnv + "; set +a; exec runuser -u vpn-admin -- " + panelServer + " artisan \"$@\""
	return exec.Command("/bin/sh", append([]string{"-c", script, "sh"}, args...)...) //nolint:gosec
}

const (
	numCode    = 1
	numStatus  = 2
	numRestart = 3
	numSupport = 4
	numBackup  = 5
	numSignOut = 6
	numHelp    = 9
)

func (g *gateway) catalog() console.Catalog {
	status := func() console.Status { return gatewayStatus(g.facts(), numRestart) }
	c := console.Catalog{
		Product: "VPN Panel — шлюз офиса", ProductEN: "VPN Panel - office gateway", Version: packageVersion(),
		Status: status,
		Actions: []console.Action{
			{Number: numCode, Command: "code", Title: "Код входа и адрес панели", TitleEN: "Login code and panel address",
				Run: func(*console.Session) console.Result { return tell(packaged("vpn-panel-code")) }},
			{Number: numStatus, Command: "status", Title: "Состояние шлюза подробно", TitleEN: "Gateway status in detail",
				Run: func(*console.Session) console.Result { return g.details() }},
			{Number: numRestart, Command: "restart", Title: "Перезапуск панели (не интернета)", TitleEN: "Restart the panel (not the internet)",
				Danger: console.Ask, Before: g.beforeRestart, Run: func(*console.Session) console.Result { return g.restart() }},
			{Number: numSupport, Command: "support", Title: "Сведения для поддержки", TitleEN: "Support report",
				Run: func(*console.Session) console.Result { return tell(packaged("vpn-panel-support")) }},
			{Number: numBackup, Command: "backup", Title: "Сохранить или вернуть настройки", TitleEN: "Save or restore settings",
				Run: g.backup},
			{Number: numSignOut, Command: "signout", Title: "Выйти на всех устройствах", TitleEN: "Sign out on all devices",
				Danger: console.Guarded, Before: beforeSignOut,
				Run: func(*console.Session) console.Result { return tell(packaged("vpn-panel-reset")) }},
		},
	}
	desk := helpDesk{actions: c.Actions, status: status}
	c.Actions = append(c.Actions, console.Action{Number: numHelp, Command: "howto",
		Title: "Помощь: что делать, если…", TitleEN: "Help (Russian only)", Run: desk.run})
	return c
}

func packageVersion() string {
	out, err := exec.Command("/usr/bin/dpkg-query", "-W", "-f", "${Version}", "vpn-panel").Output()
	if err != nil || len(out) == 0 {
		return "—"
	}
	return strings.TrimSpace(string(out))
}

func (g *gateway) beforeRestart() console.Result {
	lines := []string{
		"Панель управления перезапустится: страница в браузере на несколько секунд перестанет отвечать.",
		"Не прервётся: интернет в офисе, звонки, защищённый канал. Настройки не меняются.",
	}
	var pending struct {
		Awaiting bool `json:"awaiting"`
	}
	if g.call("network.pending", &pending) && pending.Awaiting {
		lines = append(lines, "Внимание: изменение сети ждёт подтверждения. Не подтверждённое вовремя, оно вернётся к прежним настройкам само.")
	}
	var checkpoint struct {
		Exists bool `json:"exists"`
	}
	if g.call("backup.checkpoint_status", &checkpoint) && checkpoint.Exists {
		lines = append(lines, "Внимание: идёт загрузка настроек из файла. Не подтверждённая вовремя, она отменится сама.")
	}
	return console.Result{Lines: lines}
}

func (g *gateway) restart() console.Result {
	resp, err := g.client.Call("panel.restart", map[string]any{})
	switch {
	case err != nil:

		if rerr := systemctl("restart", agentUnit, panelUnit); rerr != nil {
			return console.Result{Level: console.Bad, Lines: []string{"Службы панели не перезапустились.", "Перезагрузите шлюз; если не поможет — соберите сведения для поддержки."}}
		}
	case resp.Error != nil:
		return console.Result{Level: console.Bad, Lines: []string{"Не получилось: " + resp.Error.Message + "."}}
	}
	for deadline := time.Now().Add(restartWait); time.Now().Before(deadline); time.Sleep(time.Second) {
		if unitActive(panelUnit) && panelAnswers() {
			return console.Result{Level: console.OK, Lines: []string{"Панель перезапущена и отвечает."}}
		}
	}
	return console.Result{Level: console.Bad, Lines: []string{"Панель перезапущена, но пока не отвечает.", "Подождите минуту и проверьте состояние; если не изменилось — соберите сведения для поддержки."}}
}

func beforeSignOut() console.Result {
	return console.Result{Lines: []string{
		"Все устройства, с которых входили в панель, будут отключены от неё.",
		"Войти снова можно будет только по новому коду с этого сервера.",
		"Не прервётся: интернет в офисе, звонки, защищённый канал.",
	}}
}

func (g *gateway) backup(s *console.Session) console.Result {
	s.Print(" 1  Код для выгрузки копии настроек",
		" 2  Состояние загрузки настроек из файла",
		" 3  Отменить незавершённую загрузку настроек",
		" 0  Назад", "")
	n, _ := s.Choose([]int{0, 1, 2, 3})
	switch n {
	case 1:
		return tell(packaged("vpn-panel-backup-code"))
	case 2:
		return tell(panelCommand("backup:status"))
	case 3:
		s.Print("Настройки вернутся к тем, что были до загрузки файла.")
		if !s.Confirm() {
			return console.Result{Lines: []string{"Отменено — ничего не изменилось."}}
		}
		return tell(panelCommand("backup:rollback"))
	}
	return console.Result{Quiet: true}
}

func (g *gateway) details() console.Result {
	f := g.facts()
	if !f.ServiceAnswers {
		return console.Result{Level: console.Bad, Lines: []string{"Служба шлюза не отвечает — состояние узнать не удалось."}}
	}
	lines := []string{}
	if finding, protected := vpndiag.State(f.Channel.facts()); protected {
		lines = append(lines, "Защищённый канал: "+finding.Title+".", "  "+finding.Text)
		if finding.Action != "" {
			lines = append(lines, "  Что делать: "+finding.Action)
		}
	} else {
		lines = append(lines, "Защищённый канал выключен: офис выходит в интернет напрямую.")
	}
	lines = append(lines, "", "Сетевые карты:")
	for _, card := range f.Network.Interfaces {
		if card.Loopback {
			continue
		}
		state := "кабель не подключён"
		if card.State != "DOWN" {
			state = "подключена"
		}

		var shown []string
		for _, a := range card.Addresses {
			if !strings.HasPrefix(a, "fe80:") {
				shown = append(shown, a)
			}
		}
		addr := "адреса нет"
		if len(shown) > 0 {
			addr = strings.Join(shown, ", ")
		}
		lines = append(lines, fmt.Sprintf("  %s — %s, %s", card.Name, state, addr))
	}
	var guard struct {
		InputFiltered bool  `json:"input_filtered"`
		Leaked        int64 `json:"leaked_outbound"`
	}
	if g.call("firewall.status", &guard) {
		lines = append(lines, "")
		if guard.InputFiltered {
			lines = append(lines, "Защита шлюза включена: снаружи к нему не подключиться.")
		} else {
			lines = append(lines, "Защита шлюза ещё не включена: она включается после назначения ролей сетевых карт.")
		}
	}
	var updates struct {
		Enabled bool `json:"enabled"`
	}
	if g.call("updates.status", &updates) {
		if updates.Enabled {
			lines = append(lines, "Обновления панели ставятся сами.")
		} else {
			lines = append(lines, "Обновления панели сами не ставятся — так настроено в разделе «Защита».")
		}
	}
	return console.Result{Level: console.Unknown, Lines: lines}
}

type idleInput struct {
	in    io.Reader
	limit time.Duration
}

func (r idleInput) Read(p []byte) (int, error) {
	timer := time.AfterFunc(r.limit, func() {
		_, _ = fmt.Fprintln(os.Stdout, "\n Меню закрыто: долго не было ответа.")
		os.Exit(console.ExitOK)
	})
	defer timer.Stop()
	return r.in.Read(p)
}

func confirmNumber() string {
	n, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return "4096"
	}
	return fmt.Sprint(n.Int64() + 1000)
}

func runConsole(args []string) int {
	socketPath, err := sanitizeSocketPath(os.Getenv("AGENT_SOCKET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Служба панели настроена неверно — обратитесь в поддержку.")
		return console.ExitFailed
	}
	g := &gateway{client: &agentrpc.Client{SocketPath: socketPath}}
	catalog := g.catalog()
	if err := validConsole(catalog); err != nil {
		fmt.Fprintln(os.Stderr, "Меню собрано неверно — обратитесь в поддержку.")
		return console.ExitFailed
	}
	session := console.NewSession(idleInput{os.Stdin, consoleIdle}, os.Stdout, console.Detect(os.Stdout, os.Getenv), confirmNumber)

	if len(args) > 0 && args[0] == console.CompleteWord {
		for _, word := range catalog.Words() {
			fmt.Println(word)
		}
		return console.ExitOK
	}
	if len(args) > 0 && console.IsHelp(args[0]) {
		catalog.Usage("vpn-panel", session)
		return console.ExitOK
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Запустите с правами администратора: sudo vpn-panel")
		return console.ExitFailed
	}
	if len(args) > 0 {
		return console.RunCommand(catalog, "vpn-panel", args[0], session)
	}
	if !console.IsTerminal(os.Stdin) {
		catalog.Usage("vpn-panel", session)
		return console.ExitOK
	}
	return console.Run(catalog, session)
}
