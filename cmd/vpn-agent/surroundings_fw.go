package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftforeign"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

const (
	factForwardCut = "surroundings.forward_cut"
	factForwardOff = "surroundings.forward_off"
	factOwnTable   = "surroundings.own_table"
	factDHCPLAN    = "surroundings.dhcp_lan"
)

var ownTables = []string{"inet vpn_panel", "inet " + nftgen.DHCPWatchTable}

var ruleSourceUnits = []string{"netfilter-persistent", "docker", "firewalld", "ufw", "nftables"}

func (f *firewallApplier) surroundFirewallProbes() []surroundProbe {
	w := &witnessState{}
	return []surroundProbe{
		{ids: []string{factForwardCut}, run: func(_ context.Context, env surroundEnv) []observation {
			return probeForwardCut(env, f.guardView(), w)
		}},
		{ids: []string{factForwardOff, factOwnTable}, run: func(context.Context, surroundEnv) []observation {
			return probeOwnTable(f.guardView(), time.Now())
		}},
		{ids: []string{factDHCPLAN}, run: func(context.Context, surroundEnv) []observation {
			built, reset, caps := f.dhcpWatchOn()
			return probeDHCPLAN(f.guardView(), built, reset, caps)
		}},
	}
}

func (f *firewallApplier) dhcpWatchOn() (built, reset bool, caps hostcaps.Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dhcpBuilt != nil, f.dhcpReset, capsOf(f.caps).Answer("nft.dhcp_watch")
}

type witnessState struct {
	handle      int64
	early, late int64
	verdict     witnessVerdict
}

type witnessVerdict int

const (
	witnessNone witnessVerdict = iota
	witnessPass
	witnessCut
)

func (w *witnessState) observe(handle, early, late int64, ok bool) witnessVerdict {
	if !ok {
		*w = witnessState{}
		return witnessNone
	}
	if handle != w.handle || early < w.early || late < w.late {
		*w = witnessState{handle: handle, early: early, late: late}
		return witnessNone
	}
	de, dl := early-w.early, late-w.late
	switch {
	case dl > 0:

		w.verdict = witnessPass
	case de > 0:
		w.verdict = witnessCut
	default:

		return w.verdict
	}
	w.early, w.late = early, late
	return w.verdict
}

func readWitness() (handle, early, late int64, ok bool) {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return 0, 0, 0, false
	}
	out, err := runOut(nft, "-j", "-t", "list", "table", "inet", "vpn_panel")
	if err != nil {
		return 0, 0, 0, false
	}
	return parseWitness(out)
}

func parseWitness(out []byte) (handle, early, late int64, ok bool) {
	var doc struct {
		Nftables []struct {
			Table *struct {
				Handle int64 `json:"handle"`
			} `json:"table"`
			Counter *struct {
				Name    string `json:"name"`
				Packets int64  `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return 0, 0, 0, false
	}
	var hasEarly, hasLate bool
	for _, it := range doc.Nftables {
		switch {
		case it.Table != nil:
			handle = it.Table.Handle
		case it.Counter != nil && it.Counter.Name == nftgen.SeenEarlyCounter:
			early, hasEarly = it.Counter.Packets, true
		case it.Counter != nil && it.Counter.Name == nftgen.SeenLateCounter:
			late, hasLate = it.Counter.Packets, true
		}
	}
	return handle, early, late, hasEarly && hasLate
}

type ruleSource struct {
	unit, name, subject, sentence string
}

func ruleSources(env surroundEnv) []ruleSource {
	if !env.unitsKnown {
		return nil
	}
	var out []ruleSource
	on := func(u string) bool { return env.units(u).Enabled }
	if on("netfilter-persistent") && iptablesSaveDrops(filepath.Join(env.root, "etc/iptables/rules.v4")) {
		out = append(out, ruleSource{"netfilter-persistent", "сохранённые правила iptables", "Сохранённые правила iptables",
			"Система при каждой загрузке восстанавливает сохранённые правила iptables с запретом пересылки."})
	}
	if on("ufw") && ufwEnabled(env.root) && ufwForwardDrops(env.root) {
		out = append(out, ruleSource{"ufw", "ufw", "Правила ufw", "ufw при каждой загрузке ставит свои правила с запретом пересылки."})
	}
	if on("nftables") && nftConfDrops(filepath.Join(env.root, "etc/nftables.conf")) {
		out = append(out, ruleSource{"nftables", "служба nftables", "Правила службы nftables",
			"Служба nftables при каждой загрузке ставит свои правила с запретом пересылки."})
	}
	return out
}

func iptablesSaveDrops(path string) bool {
	fh, err := os.Open(path) //nolint:gosec
	if err != nil {
		return false
	}
	defer func() { _ = fh.Close() }()
	filter := false
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "*"):
			filter = line == "*filter"
		case !filter:
		case strings.HasPrefix(line, ":FORWARD "):
			if f := strings.Fields(line); len(f) >= 2 && f[1] == "DROP" {
				return true
			}
		case strings.HasPrefix(line, "-A FORWARD "):
			if wholeForwardDrop(strings.Fields(line)[2:]) {
				return true
			}
		}
	}
	return false
}

func wholeForwardDrop(args []string) bool {
	verdict := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "!":
		case "-i", "-o", "--in-interface", "--out-interface":
			i++
		case "-j":
			if i+1 < len(args) && (args[i+1] == "DROP" || args[i+1] == "REJECT") {
				verdict = true
			}

			return verdict
		default:
			return false
		}
	}
	return false
}

func ufwForwardDrops(root string) bool {
	v := shellVarWords(filepath.Join(root, "etc/default/ufw"), "DEFAULT_FORWARD_POLICY")
	return len(v) == 1 && !strings.EqualFold(v[0], "ACCEPT")
}

func nftConfDrops(path string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(code, "hook forward") && strings.Contains(code, "policy drop") {
			return true
		}
	}
	return false
}

func probeForwardCut(env surroundEnv, v guardView, w *witnessState) []observation {
	if env.awaiting() {

		return []observation{{Fact: foreign(factForwardCut, forwardCutTitle, hostcaps.HowRun), hold: true}}
	}
	in := forwardInputs{held: v.held, working: v.working, emergency: v.emergency, witnessCaps: v.witnessCaps,
		legacyGateway: legacyvpn.Gateway(env.root), legacyTables: nftforeign.LegacyTables(env.root),
		sources: ruleSources(env)}
	if v.working && !v.emergency {
		handle, early, late, ok := readWitness()
		in.verdict, in.witness = w.observe(handle, early, late, ok), ok
	} else {
		w.observe(0, 0, 0, false)
	}
	var lans, exits []string
	if v.plan != nil {
		lans, exits = v.plan.lans, v.plan.exits
	}
	if nft, err := findBinary(nftCandidates); err == nil {
		if out, err := runOut(nft, "-j", "-t", "list", "ruleset"); err == nil {
			if vd, err := nftforeign.Analyze(out, ownTables, lans, exits); err == nil {
				in.culprits, in.analyzed = vd.Culprits, true
			}
		}
	}
	return seen(forwardCutFact(in))
}

const forwardCutTitle = "Чужие правила фаервола"

type forwardInputs struct {
	witness bool
	verdict witnessVerdict

	held, working, emergency bool

	witnessCaps   hostcaps.Answer
	culprits      []nftforeign.Culprit
	analyzed      bool
	legacyTables  []string
	sources       []ruleSource
	legacyGateway bool
}

type culpritWords struct {
	short   string
	subject string
	legacy  bool
}

func nameCulprits(in forwardInputs) culpritWords {
	legacy := in.legacyGateway && (slices.ContainsFunc(in.sources, func(s ruleSource) bool {
		return s.unit == "netfilter-persistent"
	}) || slices.ContainsFunc(in.culprits, func(c nftforeign.Culprit) bool {
		return c.Family == "ip" && c.Table == "filter" && !c.Docker
	}))
	iptables := nftforeign.Name(nftforeign.Culprit{Family: "ip", Table: "filter"})
	switch {
	case legacy:
		return culpritWords{"старый скрипт vpn.sh", "Правила фаервола старого скрипта vpn.sh", true}
	case len(in.culprits) > 0:
		switch n := nftforeign.Name(in.culprits[0]); n {
		case "Docker", "firewalld":
			return culpritWords{n, "Правила фаервола " + n, false}
		case iptables:
			return culpritWords{n, "Правила старого фаервола (iptables)", false}
		}
	case len(in.sources) > 0:
		return culpritWords{in.sources[0].name, in.sources[0].subject, false}
	case len(in.legacyTables) > 0:
		return culpritWords{iptables, "Правила старого фаервола (iptables)", false}
	}
	return culpritWords{"чужие правила фаервола", "Чужие правила фаервола", false}
}

func forwardCutFact(in forwardInputs) hostcaps.Fact {
	f := foreign(factForwardCut, forwardCutTitle, hostcaps.HowRun)
	words := nameCulprits(in)
	foreignRules := len(in.culprits) > 0 || len(in.legacyTables) > 0
	support := forwardSupport(in.culprits, in.sources, in.legacyTables)
	yes := func(level, how, found string) hostcaps.Fact {
		f.Answer, f.Level, f.How, f.Value, f.Found, f.Support = hostcaps.Yes, level, how, words.short, found, support
		if words.legacy {
			f.Cause = hostcaps.CauseLegacy
		}
		return f
	}
	unknown := func(why string) hostcaps.Fact {
		f.Found, f.Support = why, support
		if foreignRules {
			f.Value = words.short
			f.Found = "На сервере есть " + lowerFirst(words.subject) + ". " + why
		}
		return f
	}

	outside := slices.ContainsFunc(in.culprits, func(c nftforeign.Culprit) bool { return c.OutsideWitness })

	if in.witness {
		switch {
		case in.verdict == witnessCut:
			return yes(hostcaps.LevelError, hostcaps.HowCounter, forwardCutText(words))
		case in.verdict == witnessNone:
			return unknown("Проходит ли интернет офиса, шлюз увидит, когда компьютеры офиса начнут выходить в интернет.")
		case outside:
			return unknown("Они стоят вне проверки шлюза, и шлюз не видит, режут ли они интернет офиса. Если у офиса нет интернета, начните с них.")
		case len(in.sources) > 0:
			return yes(hostcaps.LevelWarn, hostcaps.HowCounter, forwardSourceText(words, in.sources[0]))
		case foreignRules:
			return yes(hostcaps.LevelInfo, hostcaps.HowCounter,
				words.subject+" есть на сервере, но сейчас не мешают интернету офиса и пропадут после перезагрузки.")
		}
		f.Answer, f.How = hostcaps.No, hostcaps.HowCounter
		return f
	}

	if in.held {

		switch {
		case in.emergency:
			return unknown("Пока шлюз возвращает свои правила, офис закрыт от интернета. Проходит ли интернет офиса, шлюз проверит, когда правила вернутся.")
		case !in.working:
			return unknown("Офис сейчас закрыт аварийными правилами шлюза. Проходит ли интернет офиса, шлюз проверит, когда офис снова откроется.")
		case in.witnessCaps == hostcaps.No:
			return unknown("Эта система не умеет считать трафик офиса на пересылке, поэтому шлюз сам не проверяет, проходит ли интернет офиса. Проверьте с компьютера офиса.")
		}
		return unknown("Шлюз начнёт считать трафик офиса после следующего применения настроек. До этого проверьте интернет с компьютера офиса.")
	}

	policyDrop := slices.ContainsFunc(in.culprits, func(c nftforeign.Culprit) bool { return c.Policy == "drop" })
	switch {
	case policyDrop || len(in.sources) > 0:
		level := hostcaps.LevelInfo
		if len(in.sources) > 0 {
			level = hostcaps.LevelWarn
		}
		return yes(level, hostcaps.HowRun, forwardBeforeText(words))
	case foreignRules:
		return unknown("Режут ли они интернет офиса, шлюз проверит после применения ролей.")
	case !in.analyzed:
		return f
	}
	f.Answer = hostcaps.No
	return f
}

func forwardCutText(w culpritWords) string {
	text := w.subject + " не пропускают трафик офиса в интернет: шлюз пропускает компьютеры офиса, а дальше их режут эти правила."
	if w.legacy {
		return text + " Они возвращаются при каждой загрузке сервера. Обратитесь в поддержку."
	}
	return text + " Уберите их или выключите программу, которая их ставит."
}

func forwardSourceText(w culpritWords, src ruleSource) string {
	text := src.sentence
	if w.legacy {
		text = "Старый скрипт vpn.sh оставил правила с запретом пересылки, и система восстанавливает их при каждой загрузке."
	}
	text += " Сейчас интернет офиса проходит, но после перезагрузки офис может остаться без интернета."
	if w.legacy {
		return text + " Обратитесь в поддержку."
	}
	return text + " Выключите эту программу или уберите из её правил запрет пересылки."
}

func forwardBeforeText(w culpritWords) string {
	if w.legacy {
		return "Старый скрипт vpn.sh запрещает пересылку трафика своими правилами фаервола. После применения ролей они могут не пропустить трафик офиса в интернет."
	}
	return w.subject + " запрещают пересылку трафика. После применения ролей они могут не пропустить трафик офиса в интернет. Уберите их или выключите программу, которая их ставит."
}

func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToLower(string(r[0])) + string(r[1:])
}

func forwardSupport(culprits []nftforeign.Culprit, sources []ruleSource, legacyTabs []string) []string {
	var out []string
	for _, c := range culprits {
		line := c.Family + " " + c.Table
		if c.Policy != "" {
			line += " policy " + c.Policy
		}
		if c.Drops {
			line += " drops"
		}
		if c.Opaque {
			line += " opaque"
		}
		out = append(out, line)
	}
	for _, s := range sources {
		out = append(out, s.unit+".service")
	}
	for _, t := range legacyTabs {
		out = append(out, "iptables-legacy "+t)
	}
	return out
}

func probeOwnTable(v guardView, now time.Time) []observation {
	off := foreign(factForwardOff, "Пересылка трафика", hostcaps.HowFile)
	off.Answer = hostcaps.No
	switch {
	case !v.working || !v.forward || v.emergency:
	case v.fwdOffNow:
		off.Answer, off.Level = hostcaps.Yes, hostcaps.LevelError
		off.Found = "Пересылка трафика на сервере выключена: офис без интернета. Её выключила другая программа; шлюз включит её снова."
	case !v.fwdOffAt.IsZero() && now.Sub(v.fwdOffAt) < guardCalm:
		off.Answer, off.Level = hostcaps.Yes, hostcaps.LevelWarn
		off.Found = "Другая программа выключала пересылку трафика, и офис на время оставался без интернета. Шлюз включил её снова. Если это повторится, найдите программу, которая её выключает."
	}

	own := foreign(factOwnTable, "Правила шлюза", hostcaps.HowRun)
	own.Answer = hostcaps.No
	if !v.erasedAt.IsZero() {
		who := writerName(v.eraser)
		named := ""
		if who != "" {
			named = ": " + who
		}
		own.Answer, own.Value = hostcaps.Yes, who
		own.Support = []string{writerLine(v.eraser)}
		switch {
		case v.failed:
			own.Level = hostcaps.LevelError
			own.Found = "Другая программа стёрла правила шлюза" + named + ". Вернуть их не удалось, офис закрыт от интернета. Нажмите «Применить» на странице «Сеть»."
		case v.emergency:
			own.Level = hostcaps.LevelError
			own.Found = "Другая программа раз за разом стирает правила шлюза" + named + ". Шлюз возвращает их, но пока их стирают, офис закрыт от интернета. Выключите эту программу."
		default:
			own.Level = hostcaps.LevelWarn
			own.Found = "Другая программа стёрла правила шлюза" + named + ". Шлюз вернул их сам, офис работает. Если это повторится, выключите эту программу."
		}
	}
	return seen(off, own)
}

func writerName(w writer) string {
	switch unit := strings.TrimSuffix(w.unit, ".service"); {
	case unit == "nftables":
		return "служба nftables"
	case unit == "netfilter-persistent":
		return "восстановление сохранённых правил iptables"
	case unit == "docker" || w.comm == "dockerd":
		return "Docker"
	case unit == "firewalld" || w.comm == "firewalld":
		return "firewalld"
	case unit == "ufw":
		return "ufw"
	case strings.HasPrefix(unit, "session-") || strings.HasPrefix(unit, "user@"):
		return "команда в консоли"
	case unit == "cron":
		return "задание по расписанию"
	case strings.HasPrefix(w.comm, "iptables") || strings.HasPrefix(w.comm, "ip6tables") ||
		strings.HasPrefix(w.comm, "xtables"):
		return "команда iptables"
	case w.comm == "nft":
		return "команда nft"
	}
	return w.comm
}

const dhcpLANTitle = "Раздача адресов в сети офиса"

func probeDHCPLAN(v guardView, built, reset bool, caps hostcaps.Answer) []observation {
	f := foreign(factDHCPLAN, dhcpLANTitle, hostcaps.HowRun)
	switch {
	case !v.held:
		f.Found = "Шлюз начнёт слушать сеть офиса, когда роли будут применены."
		return seen(f)
	case v.emergency || !v.working:
		f.Found = "Пока офис закрыт аварийными правилами шлюза, шлюз не слушает сеть офиса."
		return seen(f)
	case caps == hostcaps.No:
		for _, o := range nftgen.Options {
			if o.ID == "nft.dhcp_watch" {
				f.Found = o.Missing
			}
		}
		return seen(f)
	case v.plan == nil || caps != hostcaps.Yes || !built:

		f.Found = "Шлюз готовит наблюдение за сетью офиса."
		return seen(f)
	}
	got, windowOpen, ok := dhcpWatchRead()
	if !ok {
		f.Found = "Шлюз готовит наблюдение за сетью офиса."
		return seen(f)
	}
	return seen(dhcpLANFact(got, windowOpen, reset))
}

func dhcpLANFact(got []dhcpSeen, windowOpen, reset bool) hostcaps.Fact {
	f := foreign(factDHCPLAN, dhcpLANTitle, hostcaps.HowRun)
	if len(got) > 0 {
		var addrs, support []string
		for _, s := range got {
			if !slices.Contains(addrs, s.addr) {
				addrs = append(addrs, s.addr)
			}
			support = append(support, s.mac+" "+s.addr)
		}
		sort.Strings(addrs)
		sort.Strings(support)
		f.Answer, f.Level, f.Value, f.Support = hostcaps.Yes, hostcaps.LevelWarn, strings.Join(addrs, ", "), support
		f.Found = "В сети офиса работает ещё один сервер раздачи адресов (" + f.Value + "). Часть компьютеров может получить адрес от него и выходить в интернет мимо шлюза. Выключите DHCP на этом устройстве: обычно это роутер или точка доступа."
		return f
	}
	if windowOpen {
		f.Found = "Шлюз слушает сеть офиса. Второй сервер раздачи адресов виден, только когда отвечает компьютерам, поэтому ответ будет в течение суток."

		f.Reset = reset
		return f
	}
	f.Answer = hostcaps.No
	return f
}
