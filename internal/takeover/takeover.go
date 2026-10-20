package takeover

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

type UnitState struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
	Masked  bool `json:"masked"`

	FileInEtc bool `json:"file_in_etc"`
}

const (
	KindService  = "service"
	KindNetplan  = "netplan"
	KindFirewall = "firewall"
	KindFile     = "file"
	KindSudoers  = "sudoers"
	KindCron     = "cron"
	KindSysctl   = "sysctl"
	KindScript   = "script"
	KindLocked   = "locked"
)

type Item struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`

	Title   string `json:"title"`
	Found   string `json:"found"`
	Checked bool   `json:"checked"`
	Locked  bool   `json:"locked"`

	Support []string `json:"support,omitempty"`

	Order int  `json:"order"`
	Step1 []Op `json:"step1,omitempty"`
	Step3 []Op `json:"step3,omitempty"`

	Undo []Op `json:"undo,omitempty"`
}

func (it Item) RetiresDHCP() bool { return it.Order == orderDHCP }

type Plan struct {
	Digest string `json:"digest"`
	Items  []Item `json:"items"`
}

const (
	orderDHCP = iota + 1
	orderForward
	orderOther
	orderUSB
	orderScript
)

type Env struct {
	Root string

	Units      func(name string) UnitState
	UnitsKnown bool
	Legacy     legacyvpn.Report

	LegacyGateway bool

	DHCPUnits []string

	PlanCards []string
	AllCards  []string
	CardMACs  map[string]string

	OwnNetplan string

	ForwardSources []string

	ForwardBootFiles []string
	Docker, VM       bool

	HomeScripts []string
}

func Units(more ...string) []string {
	out := []string{unitApache, unitISC, unitCron, unitPersistent, unitOpenVPN, unitMTU,
		unitFirewalld, unitNftables, unitUFW, legacyvpn.TerminalUnit}
	out = append(out, legacyvpn.Units()...)
	for _, t := range legacyvpn.Tunnels() {
		out = append(out, t.Unit)
	}
	for _, d := range legacyvpn.Daemons() {
		out = append(out, d.Unit)
	}
	return sortedSet(append(out, more...), fullUnit)
}

func Build(env Env) Plan {
	b := &builder{env: normalize(env)}
	if b.env.LegacyGateway {
		b.legacy()
	}
	b.foreign()
	items := b.items
	slices.SortFunc(items, func(x, y Item) int {
		if x.Order != y.Order {
			return x.Order - y.Order
		}
		return strings.Compare(x.ID, y.ID)
	})
	for i := range items {
		items[i].Support = support(items[i], b.extra[items[i].ID])
		items[i].Checked = !items[i].Locked && !b.unchecked[items[i].ID]
	}
	return Plan{Digest: Digest(items), Items: items}
}

func (p Plan) Select(ids []string) (Plan, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := Plan{Digest: p.Digest}
	known := map[string]bool{}
	var errs []error
	for _, it := range p.Items {
		known[it.ID] = true
		if !want[it.ID] {
			continue
		}
		if it.Locked {
			errs = append(errs, fmt.Errorf("пункт %q заперт: его панель не трогает", it.ID))
			continue
		}
		out.Items = append(out.Items, it)
	}
	for id := range want {
		if !known[id] {
			errs = append(errs, fmt.Errorf("пункта %q нет в плане", id))
		}
	}
	if len(errs) > 0 {
		slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
		return Plan{}, errors.Join(errs...)
	}
	return out, nil
}

func normalize(env Env) Env {
	env.DHCPUnits = sortedSet(env.DHCPUnits, fullUnit)
	env.ForwardSources = sortedSet(env.ForwardSources, fullUnit)
	env.PlanCards = sortedSet(env.PlanCards, nil)
	env.AllCards = sortedSet(env.AllCards, nil)
	env.ForwardBootFiles = sortedSet(env.ForwardBootFiles, rooted)
	env.HomeScripts = sortedSet(env.HomeScripts, scriptInHome)
	if !env.UnitsKnown {
		env.Units = nil
	}
	return env
}

func sortedSet(in []string, norm func(string) string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if norm != nil {
			if s = norm(s); s == "" {
				continue
			}
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func rooted(p string) string { return filepath.Join("/", filepath.Clean(p)) }

func scriptInHome(p string) string {
	p = rooted(p)
	dir, base := filepath.Split(p)
	if base != legacyvpn.ScriptName {
		return ""
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "root":
	case len(parts) == 2 && parts[0] == "home":
	default:
		return ""
	}
	return p
}

var unitSuffixes = []string{".service", ".socket", ".timer", ".target", ".path", ".mount"}

func unitName(u string) string {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(u, s) {
			return u
		}
	}
	return u + ".service"
}

func fullUnit(u string) string {
	if u = unitName(u); validUnit(u) {
		return u
	}
	return ""
}

func validUnit(u string) bool {
	stem := ""
	for _, s := range unitSuffixes {
		if t, ok := strings.CutSuffix(u, s); ok {
			stem = t
			break
		}
	}
	if stem == "" {
		return false
	}
	for _, r := range u {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(":_.@-", r)
		if !ok {
			return false
		}
	}
	return true
}

func shortUnit(u string) string { return strings.TrimSuffix(u, ".service") }

type builder struct {
	env   Env
	items []Item

	extra map[string][]string

	unchecked map[string]bool
}

func (b *builder) add(it Item) {
	for i := range b.items {
		if b.items[i].ID == it.ID {
			b.items[i].Step1 = append(b.items[i].Step1, it.Step1...)
			b.items[i].Step3 = append(b.items[i].Step3, it.Step3...)
			b.items[i].Undo = append(b.items[i].Undo, it.Undo...)
			return
		}
	}
	b.items = append(b.items, it)
}

func (b *builder) note(id string, s ...string) {
	if b.extra == nil {
		b.extra = map[string][]string{}
	}
	b.extra[id] = append(b.extra[id], s...)
}

func (b *builder) has(id string) bool {
	return slices.ContainsFunc(b.items, func(it Item) bool { return it.ID == id })
}

func (b *builder) st(unit string) UnitState {
	if b.env.Units == nil {
		return UnitState{}
	}
	return b.env.Units(unit)
}

func (b *builder) uncheck(id string) {
	if b.unchecked == nil {
		b.unchecked = map[string]bool{}
	}
	b.unchecked[id] = true
}

func (b *builder) unitInEtc(unit string) bool {
	s := b.st(unit)
	return !s.Masked && (s.FileInEtc || b.isFile(legacyvpn.UnitDir+"/"+unit))
}

func (b *builder) present(unit string) bool {
	s := b.st(unit)
	return !s.Masked && (s.Enabled || s.Active || b.unitInEtc(unit))
}

var packageUnitDirs = []string{"/lib/systemd/system", "/usr/lib/systemd/system"}

func (b *builder) packageUnit(unit string) bool {
	names := []string{unit}
	if at := strings.IndexByte(unit, '@'); at >= 0 {
		names = append(names, unit[:at+1]+unit[strings.LastIndexByte(unit, '.'):])
	}
	for _, d := range packageUnitDirs {
		for _, n := range names {
			if b.isFile(d + "/" + n) {
				return true
			}
		}
	}
	return false
}

func (b *builder) path(p string) string { return filepath.Join(b.env.Root, p) }

func (b *builder) isFile(p string) bool {
	fi, err := os.Stat(b.path(p))
	return err == nil && fi.Mode().IsRegular()
}

func (b *builder) isDir(p string) bool {
	fi, err := os.Lstat(b.path(p))
	return err == nil && fi.IsDir()
}

func (b *builder) read(p string) ([]byte, bool) {
	data, err := os.ReadFile(b.path(p)) //nolint:gosec
	return data, err == nil
}

func (b *builder) marker(id string) bool { return slices.Contains(b.env.Legacy.Markers, id) }

type retirement struct {
	ops, after []Op
	reload     bool
}

func (b *builder) retire(r *retirement, unit string, stop, mask bool) {
	r.ops = append(r.ops, Op{Kind: OpDisable, Unit: unit})
	if mask && b.unitInEtc(unit) {
		if stop {
			r.ops = append(r.ops, Op{Kind: OpStop, Unit: unit})
		}
		r.ops = append(r.ops, Op{Kind: OpBackup, Path: legacyvpn.UnitDir + "/" + unit})
		r.reload = true
		if b.packageUnit(unit) {
			r.after = append(r.after, Op{Kind: OpMask, Unit: unit})
		}
		return
	}
	if mask {
		r.ops = append(r.ops, Op{Kind: OpMask, Unit: unit})
	}
	if stop {
		r.ops = append(r.ops, Op{Kind: OpStop, Unit: unit})
	}
}

func (r retirement) list() []Op {
	out := slices.Clone(r.ops)
	if r.reload {
		out = append(out, Op{Kind: OpExec, Command: CmdDaemonReload})
	}
	return append(out, r.after...)
}

func (b *builder) retireAll(unit string, stop, mask bool) []Op {
	var r retirement
	b.retire(&r, unit, stop, mask)
	return r.list()
}

func support(it Item, extra []string) []string {
	var out []string
	for _, ops := range [][]Op{it.Step1, it.Step3, it.Undo} {
		for _, op := range ops {
			for _, s := range []string{op.Unit, op.Path} {
				if s != "" && !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
	}
	for _, s := range extra {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func activeKeys(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimPrefix(strings.TrimSpace(line), "-")
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		k, _, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		key := strings.ReplaceAll(strings.TrimSpace(k), "/", ".")
		if !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	return out
}

func forwardKey(k string) bool {
	return k == "net.ipv4.ip_forward" ||
		(strings.HasPrefix(k, "net.ipv4.conf.") && strings.HasSuffix(k, ".forwarding"))
}

func hasTrimmedLine(data []byte, s string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == s {
			return true
		}
	}
	return false
}

func listRU(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " и " + words[len(words)-1]
}
