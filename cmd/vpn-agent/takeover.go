package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/sockowner"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
)

type takeoverSys struct {
	root      string
	systemctl func(args ...string) error

	units func(names []string) (map[string]takeover.UnitState, bool)
	nft   func(stdin []byte, args ...string) ([]byte, error)

	run      func(tool string, args ...string) (out []byte, code int, err error)
	cmdlines func() [][]byte
	bootID   func() string
	now      func() time.Time
	sleep    func(time.Duration)

	home   func(args ...string) ([]byte, error)
	cards  func() ([]netstatus.Interface, error)
	lchown func(path string, uid, gid int) error
	chmod  func(path string, mode os.FileMode) error

	spawn func(func())
}

var errTakeoverBusy = errors.New("предыдущий захват ещё доделывается")

type takeoverStatus struct {
	State   string
	Failed  int
	Residue []string
}

type takeoverRunner struct {
	mu                                sync.Mutex
	sys                               takeoverSys
	journalPath, asideDir, backupRoot string

	limiter *ratelimit.Limiter
}

func newTakeoverRunner() *takeoverRunner {
	return &takeoverRunner{sys: realTakeoverSys(), journalPath: takeoverJournalFile,
		asideDir: takeoverAsideDir, backupRoot: takeoverBackupRoot, limiter: takeoverPlanLimiter()}
}

func (r *takeoverRunner) p(path string) string { return filepath.Join(r.sys.root, path) }

func (r *takeoverRunner) readJournal() (j takeover.Journal, exists bool, err error) {
	data, err := os.ReadFile(r.p(r.journalPath)) //nolint:gosec
	if errors.Is(err, fs.ErrNotExist) {
		return takeover.Journal{}, false, nil
	}
	if err != nil {
		return takeover.Journal{}, true, err
	}
	j, err = takeover.ParseJournal(data)
	return j, true, err
}

func (r *takeoverRunner) saveJournal(j takeover.Journal) error {
	data, err := j.Marshal()
	if err != nil {
		return err
	}
	journal := r.p(r.journalPath)
	return durable.Write(journal, data, 0o600)
}

func (r *takeoverRunner) dropJournal() error {
	journal := r.p(r.journalPath)
	return durable.Remove(journal)
}

var takeoverExtraUnits = []string{"firewalld", "docker", "libvirtd"}

func (r *takeoverRunner) plan(lans, planCards []string) (takeover.Plan, error) {
	env, err := r.env(lans, planCards)
	if err != nil {
		return takeover.Plan{}, err
	}
	return takeover.Build(env), nil
}

func (r *takeoverRunner) env(lans, planCards []string) (takeover.Env, error) {
	cards, err := r.sys.cards()
	if err != nil {
		return takeover.Env{}, fmt.Errorf("карты машины: %w", err)
	}
	owners := dhcpSocketOwners(r.sys.root)
	more := slices.Concat(dhcpServers, ruleSourceUnits, takeoverExtraUnits)
	for _, o := range owners {
		more = append(more, o.unit)
	}
	states, known := r.sys.units(takeover.Units(more...))
	state := func(u string) (takeover.UnitState, bool) {
		if !known {
			return takeover.UnitState{}, false
		}
		s, ok := states[u]
		return s, ok
	}
	env := takeover.Env{
		Root:       r.sys.root,
		UnitsKnown: known,
		Units:      func(u string) takeover.UnitState { return states[u] },
		Legacy:     r.legacyReport(legacyUnits(states, known)),
		DHCPUnits:  dhcpHolders(r.sys.root, lans, cards, owners, state),
		PlanCards:  planCards,
		CardMACs:   map[string]string{},
		OwnNetplan: filepath.Base(netplanFile),
		ForwardSources: forwardSourceUnits(surroundEnv{root: r.sys.root, unitsKnown: known,
			units: func(u string) svcState {
				s := states[u+".service"]
				return svcState{Enabled: s.Enabled, Active: s.Active}
			}}, state),
		ForwardBootFiles: forwardBootFiles(r.sys.root),
		HomeScripts:      r.homeScripts(),
	}
	env.LegacyGateway = env.Legacy.Gateway
	for _, c := range cards {
		env.AllCards = append(env.AllCards, c.Name)
		if c.MAC != "" {
			env.CardMACs[c.Name] = c.MAC
		}
	}
	_, env.Docker = state("docker.service")
	_, env.VM = state("libvirtd.service")
	return env, nil
}

func (r *takeoverRunner) legacyReport(units legacyvpn.UnitState) legacyvpn.Report {
	residue, _ := r.taken()
	return legacyvpn.Detect(r.sys.root, units).Without(residue)
}

func legacyUnits(states map[string]takeover.UnitState, known bool) legacyvpn.UnitState {
	if !known {
		return nil
	}
	return func(u string) (bool, bool) { s := states[u]; return s.Enabled, s.Active }
}

func forwardSourceUnits(env surroundEnv, state func(string) (takeover.UnitState, bool)) []string {
	var out []string
	for _, s := range ruleSources(env) {
		out = append(out, s.unit)
	}
	if st, ok := state("firewalld.service"); ok && st.Enabled {
		out = append(out, "firewalld")
	}
	return out
}

func (r *takeoverRunner) homeScripts() []string {
	out, err := r.sys.home("scan")
	if err != nil {
		log.Printf("takeover: home scan: %v", err)
		return nil
	}
	paths, err := parseHomeScan(out)
	if err != nil {
		log.Printf("takeover: home scan: %v", err)
		return nil
	}
	return paths
}

type dhcpSocket struct {
	addr netip.Addr
	unit string
}

func dhcpSocketOwners(root string) []dhcpSocket {
	socks, err := sockowner.List(root, "udp", 67)
	if err != nil {
		return nil
	}
	inodes := make([]uint64, 0, len(socks))
	for _, s := range socks {
		inodes = append(inodes, s.Inode)
	}
	owners, err := sockowner.Owners(root, inodes)
	if err != nil {
		return nil
	}
	var out []dhcpSocket
	for _, s := range socks {
		o, ok := owners[s.Inode]
		if !ok || o.Unit == "" || o.Unit == keaUnit+".service" {
			continue
		}
		out = append(out, dhcpSocket{addr: s.Addr, unit: o.Unit})
	}
	return out
}

func dhcpHolders(root string, lans []string, cards []netstatus.Interface, socks []dhcpSocket,
	state func(string) (takeover.UnitState, bool)) []string {
	onLAN := func(cc []string) bool {
		if len(lans) == 0 {
			return true
		}
		for _, c := range cc {
			if c == "*" || slices.Contains(lans, c) {
				return true
			}
		}
		return false
	}
	var out []string
	add := func(u string) {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	for _, s := range socks {
		short := strings.TrimSuffix(s.unit, ".service")
		if !s.addr.IsUnspecified() {
			if c := cardOfAddress(cards, s.addr); c != "" && onLAN([]string{c}) {
				add(s.unit)
			}
			continue
		}

		if cc, _ := dhcpConfigCards(root, short); len(cc) == 0 || onLAN(cc) {
			add(s.unit)
		}
	}

	for _, short := range dhcpServers {
		st, ok := state(short + ".service")
		if !ok || !st.Enabled {
			continue
		}
		if cc, _ := dhcpConfigCards(root, short); len(cc) > 0 && onLAN(cc) {
			add(short + ".service")
		}
	}
	slices.Sort(out)
	return out
}

func cardOfAddress(cards []netstatus.Interface, a netip.Addr) string {
	for _, c := range cards {
		for _, cidr := range c.Addresses {
			if pfx, err := netip.ParsePrefix(cidr); err == nil && pfx.Addr() == a {
				return c.Name
			}
		}
	}
	return ""
}

func (r *takeoverRunner) begin(sel takeover.Plan) (takeover.Journal, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, exists, err := r.readJournal(); exists {

		if err != nil || old.Stage != takeover.StageDone {
			return takeover.Journal{}, errTakeoverBusy
		}
		if err := r.dropJournal(); err != nil {
			return takeover.Journal{}, err
		}
	}
	j := takeover.Journal{
		Plan:      sel,
		Stage:     takeover.StageWindow,
		Started:   r.sys.now().UTC().Format(time.RFC3339),
		Step1Boot: r.sys.bootID(),
		Before:    r.before(sel),
	}
	if err := r.saveJournal(j); err != nil {
		return takeover.Journal{}, fmt.Errorf("журнал захвата: %w", err)
	}
	for _, p := range j.Step1() {
		err := r.do(&j, p)
		if err == nil {
			err = r.saveJournal(j)
		}
		if err != nil {
			r.rollbackStep1(&j)
			return takeover.Journal{}, fmt.Errorf("пункт %s: %w", p.ItemID, err)
		}
	}
	return j, nil
}

func (r *takeoverRunner) before(sel takeover.Plan) map[string]takeover.UnitState {
	names := planUnits(sel)
	if len(names) == 0 {
		return nil
	}
	states, ok := r.sys.units(names)
	if !ok {
		return nil
	}
	out := map[string]takeover.UnitState{}
	for _, u := range names {
		if s, known := states[u]; known {
			out[u] = s
		}
	}
	return out
}

func planUnits(p takeover.Plan) []string {
	var out []string
	for _, it := range p.Items {
		for _, ops := range [][]takeover.Op{it.Step1, it.Step3, it.Undo} {
			for _, op := range ops {
				if op.Unit != "" && !slices.Contains(out, op.Unit) {
					out = append(out, op.Unit)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func (r *takeoverRunner) rollbackStep1(j *takeover.Journal) {
	if err := r.restoreAsideLocked(j); err != nil {
		log.Printf("takeover: aside files not restored: %v", err)
	}
	r.undoLocked(j)
	if err := r.dropJournal(); err != nil {
		log.Printf("takeover: journal not removed: %v", err)
	}
}

func (r *takeoverRunner) restoreAside() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, exists, err := r.readJournal()
	if err != nil || !exists || j.Stage != takeover.StageWindow {
		return err
	}
	return r.restoreAsideLocked(&j)
}

func (r *takeoverRunner) restoreAsideLocked(j *takeover.Journal) error {
	for len(j.Aside) > 0 {
		a := j.Aside[0]
		saved := r.p(a.Saved)
		data, err := os.ReadFile(saved) //nolint:gosec
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err == nil {
			path := r.p(a.Path)
			if err := durable.Write(path, data, fs.FileMode(a.Mode), durable.Owner(a.UID, a.GID)); err != nil {
				return err
			}
			if err := durable.Remove(saved); err != nil {
				return err
			}
		}
		j.Aside = j.Aside[1:]
		if err := r.saveJournal(*j); err != nil {
			return err
		}
	}
	return nil
}

func (r *takeoverRunner) undoUnits() {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, exists, err := r.readJournal()
	if err != nil {
		log.Printf("takeover: journal not read: %v", err)
		return
	}
	if !exists || j.Stage != takeover.StageWindow {
		return
	}
	if err := r.restoreAsideLocked(&j); err != nil {
		log.Printf("takeover: aside files not restored: %v", err)
	}
	r.undoLocked(&j)
	if err := r.dropJournal(); err != nil {
		log.Printf("takeover: journal not removed: %v", err)
	}
}

func (r *takeoverRunner) undoLocked(j *takeover.Journal) {
	for _, p := range j.Undo(r.sys.bootID()) {
		if err := r.do(j, p); err != nil {
			log.Printf("takeover: undo %s %s: %v", p.ItemID, p.Op.Kind, err)
		}
	}
}

func (r *takeoverRunner) confirm() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, exists, err := r.readJournal()
	if err != nil || !exists || j.Stage != takeover.StageWindow {
		return err
	}
	j.Stage = takeover.StageFinishing
	return r.saveJournal(j)
}

func (r *takeoverRunner) finish() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, exists, err := r.readJournal()
	if err != nil {
		return false, err
	}
	switch {
	case !exists, j.Stage == takeover.StageDone:
		return true, nil
	case j.Stage == takeover.StageWindow:
		return false, errors.New("окно сети ещё не подтверждено")
	}
	if j.Backup == "" {
		j.Backup = r.backupRoot + "/" + takeoverBackupPrefix + r.sys.now().UTC().Format(takeoverBackupStamp)
		if err := durable.MkdirAll(r.p(j.Backup), 0o700); err != nil {
			return false, err
		}
		if err := r.saveJournal(j); err != nil {
			return false, err
		}
	}
	all, err := j.Finish(r.sys.bootID(), func(p takeover.PendingOp) error { return r.do(&j, p) }, r.saveJournal)
	if err != nil {
		return false, err
	}
	if all {
		j.Stage, j.Residue = takeover.StageDone, r.remainingMarkers()
	} else {
		j.Stage = takeover.StagePartial
	}
	return all, r.saveJournal(j)
}

func (r *takeoverRunner) remainingMarkers() []string {
	states, known := r.sys.units(takeover.Units())
	return legacyvpn.Detect(r.sys.root, legacyUnits(states, known)).Markers
}

func (r *takeoverRunner) recoverOnStart(windowOpen bool) {
	j, exists, err := r.readJournal()
	if err != nil {
		log.Printf("takeover: journal not read, nothing recovered: %v", err)
		return
	}
	if !exists {
		return
	}
	switch j.Stage {
	case takeover.StageWindow:
		if windowOpen {
			log.Printf("takeover: window was open, restoring step 1")
			r.undoUnits()
			return
		}
		if err := r.confirm(); err != nil {
			log.Printf("takeover: confirm after restart: %v", err)
			return
		}
		fallthrough
	case takeover.StageFinishing, takeover.StagePartial:
		r.sys.spawn(r.finishLogged)
	}
}

func (r *takeoverRunner) finishLogged() {
	done, err := r.finish()
	switch {
	case err != nil:
		log.Printf("takeover: finish: %v", err)
	case done:
		log.Printf("takeover: finished, old gateway disabled")
	default:
		log.Printf("takeover: finish incomplete, will retry")
	}
}

func (r *takeoverRunner) units() []string {
	j, exists, err := r.readJournal()
	if err != nil || !exists {
		return nil
	}
	return planUnits(j.Plan)
}

func (r *takeoverRunner) doomed() []string {
	var out []string
	for _, u := range r.units() {
		out = append(out, strings.TrimSuffix(u, ".service"))
	}
	return out
}

func (r *takeoverRunner) residue() []string {
	res, _ := r.taken()
	return res
}

func (r *takeoverRunner) waitDHCPRetired() {
	deadline := r.sys.now().Add(confirmBudget)

	step := confirmBudget / 20
	for {
		j, exists, err := r.readJournal()
		if err != nil || !exists || j.Stage == takeover.StageWindow || !j.DHCPPending(r.sys.bootID()) {
			return
		}
		if !r.sys.now().Before(deadline) {
			log.Printf("takeover: foreign DHCP still running after confirm budget")
			return
		}
		r.sys.sleep(step)
	}
}

func (r *takeoverRunner) status() takeoverStatus {
	j, exists, err := r.readJournal()
	if err != nil || !exists {
		return takeoverStatus{State: "none"}
	}
	return takeoverStatus{State: string(j.Stage), Failed: len(j.Failed), Residue: j.Residue}
}

func (r *takeoverRunner) taken() ([]string, bool) {
	st := r.status()
	if st.State != string(takeover.StageDone) {
		return nil, false
	}
	return st.Residue, true
}
