package nftforeign

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

type Culprit struct {
	Family, Table string

	Policy string

	Drops bool

	Opaque bool

	Docker bool

	OutsideWitness bool
}

type Verdict struct {
	Culprits []Culprit

	Opaque bool

	LegacyTables []string
}

func Analyze(rulesetJSON []byte, own []string, lans, exits []string) (Verdict, error) {
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(rulesetJSON, &doc); err != nil {
		return Verdict{}, fmt.Errorf("разбор вывода nft: %w", err)
	}
	if doc.Nftables == nil {
		return Verdict{}, errors.New("в выводе nft нет списка nftables")
	}
	skip := make(map[tableKey]bool, len(own))
	for _, o := range own {
		f := strings.Fields(o)
		if len(f) != 2 {

			return Verdict{}, fmt.Errorf("своя таблица %q: нужно «семейство имя»", o)
		}
		skip[tableKey{f[0], f[1]}] = true
	}
	rs := ruleset{chains: map[chainKey]*chain{}, docker: map[tableKey]bool{}, skip: skip}
	for i, raw := range doc.Nftables {
		if err := rs.add(raw); err != nil {
			return Verdict{}, fmt.Errorf("элемент %d вывода nft: %w", i, err)
		}
	}

	flows := officeFlows(lans, exits)
	byTable := map[tableKey]*Culprit{}
	for _, k := range rs.order {
		ch := rs.chains[k]
		if ch.hook != "forward" {
			continue
		}
		w := walker{rs: &rs, seen: map[string]bool{}}
		w.walk(k, flows)
		c := byTable[k.tableKey]
		if c == nil {
			c = &Culprit{Family: k.family, Table: k.table, Docker: rs.docker[k.tableKey]}
			byTable[k.tableKey] = c
		}
		c.Policy = mergePolicy(c.Policy, ch.policy)
		c.Drops = c.Drops || w.drops
		c.Opaque = c.Opaque || w.opaque
		cuts := ch.policy == "drop" || w.drops || w.opaque
		c.OutsideWitness = c.OutsideWitness || (cuts && outsideWitness(ch.prio))
	}

	var v Verdict
	for _, c := range byTable {

		if c.Policy != "drop" && !c.Drops && !c.Opaque {
			continue
		}
		v.Culprits = append(v.Culprits, *c)
		v.Opaque = v.Opaque || c.Opaque
	}
	slices.SortFunc(v.Culprits, func(a, b Culprit) int {
		return cmp.Or(strings.Compare(a.Family, b.Family), strings.Compare(a.Table, b.Table))
	})
	return v, nil
}

var iptablesTables = map[string]bool{"filter": true, "mangle": true, "security": true}

func Name(c Culprit) string {
	switch {
	case c.Docker || strings.HasPrefix(strings.ToLower(c.Table), "docker"):
		return "Docker"
	case c.Table == "firewalld":
		return "firewalld"
	case (c.Family == "ip" || c.Family == "ip6") && iptablesTables[c.Table]:
		return "правила старого фаервола (iptables)"
	}
	return "чужие правила фаервола"
}

func LegacyTables(root string) []string {
	raw, err := os.ReadFile(filepath.Join(root, "proc", "net", "ip_tables_names")) //nolint:gosec
	if err != nil {
		return nil
	}
	out := strings.Fields(string(raw))
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

type tableKey struct{ family, table string }

type chainKey struct {
	tableKey
	name string
}

type chain struct {
	hook, policy string
	prio         json.RawMessage
	rules        []rule
}

func outsideWitness(raw json.RawMessage) bool {
	var n int
	var s string
	switch {
	case len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null":
		return true
	case json.Unmarshal(raw, &n) == nil:
	case json.Unmarshal(raw, &s) == nil:
		var ok bool
		if n, ok = nftgen.PriorityValue(s); !ok {
			return true
		}
	default:
		return true
	}
	return n <= nftgen.WitnessEarlyPriority || n >= nftgen.WitnessLatePriority
}

type ruleset struct {
	chains map[chainKey]*chain
	order  []chainKey
	docker map[tableKey]bool
	skip   map[tableKey]bool
}

func (rs *ruleset) relevant(k tableKey) bool {
	return (k.family == "ip" || k.family == "inet") && !rs.skip[k]
}

func (rs *ruleset) get(k chainKey) *chain {
	ch := rs.chains[k]
	if ch == nil {
		ch = &chain{}
		rs.chains[k] = ch
		rs.order = append(rs.order, k)
	}
	return ch
}

func (rs *ruleset) add(raw json.RawMessage) error {
	var it struct {
		Chain *struct {
			Family string          `json:"family"`
			Table  string          `json:"table"`
			Name   string          `json:"name"`
			Hook   string          `json:"hook"`
			Policy string          `json:"policy"`
			Prio   json.RawMessage `json:"prio"`
		} `json:"chain"`
		Rule *struct {
			Family string            `json:"family"`
			Table  string            `json:"table"`
			Chain  string            `json:"chain"`
			Expr   []json.RawMessage `json:"expr"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(raw, &it); err != nil {
		return err
	}
	switch {
	case it.Chain != nil:
		c := it.Chain
		tk := tableKey{c.Family, c.Table}
		if !rs.relevant(tk) {
			return nil
		}
		ch := rs.get(chainKey{tk, c.Name})
		ch.hook, ch.policy, ch.prio = c.Hook, c.Policy, c.Prio
		if c.Name == "DOCKER" || strings.HasPrefix(c.Name, "DOCKER-") {
			rs.docker[tk] = true
		}
	case it.Rule != nil:
		r := it.Rule
		tk := tableKey{r.Family, r.Table}
		if !rs.relevant(tk) {
			return nil
		}
		ch := rs.get(chainKey{tk, r.Chain})
		ch.rules = append(ch.rules, parseRule(r.Expr))
	}
	return nil
}

func mergePolicy(a, b string) string {
	switch {
	case a == "drop" || b == "drop":
		return "drop"
	case a == "accept" || b == "accept":
		return "accept"
	}
	return ""
}

type flow struct{ in, out string }

func officeFlows(lans, exits []string) []flow {
	if len(lans) == 0 {
		lans = []string{""}
	}
	if len(exits) == 0 {
		exits = []string{""}
	}
	var out []flow
	for _, l := range lans {
		for _, e := range exits {
			for _, f := range []flow{{l, e}, {e, l}} {
				if !slices.Contains(out, f) {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func flowsKey(k chainKey, flows []flow) string {
	var b strings.Builder
	b.WriteString(k.name)
	for _, f := range flows {
		b.WriteString("\x00" + f.in + "\x01" + f.out)
	}
	return b.String()
}

type walker struct {
	rs     *ruleset
	seen   map[string]bool
	drops  bool
	opaque bool
}

func (w *walker) walk(k chainKey, flows []flow) {
	id := flowsKey(k, flows)
	if w.seen[id] {
		return
	}
	w.seen[id] = true
	ch := w.rs.chains[k]
	if ch == nil {

		w.opaque = true
		return
	}
	for _, r := range ch.rules {
		left := r.narrow(flows)
		if len(left) == 0 {
			continue
		}
		w.opaque = w.opaque || r.opaque
		for _, v := range r.verdicts {
			w.drops = w.drops || v.cut
			if v.target != "" {
				w.walk(chainKey{k.tableKey, v.target}, left)
			}
		}
	}
}

type rule struct {
	conds    []cond
	v6only   bool
	verdicts []verdict
	opaque   bool
}

type verdict struct {
	cut    bool
	target string
}

type cond struct {
	out   bool
	neg   bool
	names []string
}

func (c cond) admits(f flow) bool {
	name := f.in
	if c.out {
		name = f.out
	}
	if name == "" {
		return true
	}
	hit := slices.ContainsFunc(c.names, func(p string) bool {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			return strings.HasPrefix(name, prefix)
		}
		return p == name
	})
	return hit != c.neg
}

func (r rule) narrow(flows []flow) []flow {
	if r.v6only {
		return nil
	}
	var out []flow
	for _, f := range flows {
		if !slices.ContainsFunc(r.conds, func(c cond) bool { return !c.admits(f) }) {
			out = append(out, f)
		}
	}
	return out
}

var nativeVerdicts = map[string]bool{
	"accept": true, "drop": true, "reject": true, "queue": true,
	"return": true, "continue": true, "jump": true, "goto": true, "vmap": true,
}

var xtCut = map[string]bool{"DROP": true, "REJECT": true, "QUEUE": true, "NFQUEUE": true}

var xtPass = map[string]bool{
	"ACCEPT": true, "RETURN": true, "LOG": true, "NFLOG": true, "ULOG": true,
	"MARK": true, "CONNMARK": true, "TCPMSS": true, "CT": true, "NOTRACK": true,
	"CLASSIFY": true, "DSCP": true, "TOS": true, "TTL": true, "HL": true,
	"TRACE": true, "AUDIT": true, "CHECKSUM": true, "SECMARK": true,
	"CONNSECMARK": true, "IDLETIMER": true, "SET": true, "TEE": true,
}

func parseRule(expr []json.RawMessage) rule {
	var r rule
	stmts := make([]map[string]json.RawMessage, 0, len(expr))
	native := false
	for _, raw := range expr {
		var s map[string]json.RawMessage
		if json.Unmarshal(raw, &s) != nil || len(s) != 1 {
			r.opaque = true
			continue
		}
		for k := range s {
			native = native || nativeVerdicts[k]
		}
		stmts = append(stmts, s)
	}
	for _, s := range stmts {
		for key, val := range s {
			switch key {
			case "match":
				r.addMatch(val)
			case "vmap":
				r.addVmap(val)
			case "xt":
				r.addXT(val, native)
			default:
				if nativeVerdicts[key] {
					r.addVerdict(key, val)
				}

			}
		}
	}
	return r
}

func (r *rule) addVerdict(key string, val json.RawMessage) {
	switch key {
	case "drop", "reject", "queue":
		r.verdicts = append(r.verdicts, verdict{cut: true})
	case "jump", "goto":
		var j struct {
			Target string `json:"target"`
		}
		if json.Unmarshal(val, &j) != nil || j.Target == "" {
			r.opaque = true
			return
		}
		r.verdicts = append(r.verdicts, verdict{target: j.Target})
	case "accept", "return", "continue":
	default:
		r.opaque = true
	}
}

func (r *rule) addVmap(val json.RawMessage) {
	var vm struct {
		Data json.RawMessage `json:"data"`
	}
	var set struct {
		Set []json.RawMessage `json:"set"`
	}
	if json.Unmarshal(val, &vm) != nil || json.Unmarshal(vm.Data, &set) != nil || set.Set == nil {
		r.opaque = true
		return
	}
	for _, el := range set.Set {
		var pair []json.RawMessage
		var s map[string]json.RawMessage
		if json.Unmarshal(el, &pair) != nil || len(pair) != 2 ||
			json.Unmarshal(pair[1], &s) != nil || len(s) != 1 {
			r.opaque = true
			continue
		}
		for k, v := range s {
			r.addVerdict(k, v)
		}
	}
}

func (r *rule) addXT(val json.RawMessage, native bool) {
	if bytes.Equal(bytes.TrimSpace(val), []byte("null")) {

		if !native {
			r.opaque = true
		}
		return
	}
	var x struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	switch {
	case json.Unmarshal(val, &x) != nil:
		r.opaque = true
	case x.Type == "match" || x.Type == "watcher":

	case xtCut[x.Name]:
		r.verdicts = append(r.verdicts, verdict{cut: true})
	case xtPass[x.Name]:
	default:
		r.opaque = true
	}
}

func (r *rule) addMatch(val json.RawMessage) {
	var m struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	var left struct {
		Meta *struct {
			Key string `json:"key"`
		} `json:"meta"`
		Payload *struct {
			Protocol string `json:"protocol"`
		} `json:"payload"`
	}
	if json.Unmarshal(val, &m) != nil || json.Unmarshal(m.Left, &left) != nil {
		return
	}
	if p := left.Payload; p != nil && (p.Protocol == "ip6" || p.Protocol == "icmpv6") {

		r.v6only = true
		return
	}
	if left.Meta == nil {
		return
	}
	var neg bool
	switch m.Op {
	case "==", "in", "":
	case "!=":
		neg = true
	default:
		return
	}
	switch left.Meta.Key {
	case "nfproto":
		var s string
		if !neg && json.Unmarshal(m.Right, &s) == nil && s == "ipv6" {
			r.v6only = true
		}
	case "iifname", "iif", "oifname", "oif":
		names, ok := ifaceNames(m.Right)
		if ok {
			out := left.Meta.Key == "oifname" || left.Meta.Key == "oif"
			r.conds = append(r.conds, cond{out: out, neg: neg, names: names})
		}
	}
}

func ifaceNames(right json.RawMessage) ([]string, bool) {
	var names []string
	var one string
	var set struct {
		Set json.RawMessage `json:"set"`
	}
	switch {
	case json.Unmarshal(right, &one) == nil:
		names = []string{one}
	case json.Unmarshal(right, &set) != nil || set.Set == nil:
		return nil, false
	case json.Unmarshal(set.Set, &one) == nil:
		names = []string{one}
	case json.Unmarshal(set.Set, &names) != nil:
		return nil, false
	}
	if len(names) == 0 || slices.ContainsFunc(names, func(n string) bool {
		return n == "" || strings.HasPrefix(n, "@")
	}) {
		return nil, false
	}
	return names, true
}
