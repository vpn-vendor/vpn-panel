package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/policy"
)

const rollbackUnit = "vpn-panel-rollback.service"

var rollbackUnits = systemdOps()

var rollbackOutcomeFile = "/var/lib/vpn-panel/release-outcome.json"

var panelDBPath = "/var/lib/vpn-panel/panel.sqlite"

const rollbackMaxAttempts = 2

var (
	dpkgCandidates    = []string{"/usr/bin/dpkg", "/bin/dpkg"}
	aptGetCandidates  = []string{"/usr/bin/apt-get", "/bin/apt-get"}
	aptMarkCandidates = []string{"/usr/bin/apt-mark", "/bin/apt-mark"}
)

type rollbackOutcome struct {
	Kind        string    `json:"kind"`
	ToVersion   string    `json:"to_version"`
	FromVersion string    `json:"from_version"`
	Reasons     []string  `json:"reasons"`
	At          time.Time `json:"at"`
	Attempts    int       `json:"attempts"`
}

var errDpkgBusy = errors.New("dpkg занят другим процессом")

const outcomeDeferred = "deferred"

type rollbackExec struct {
	installed   func() string
	units       *unitOps
	lockFree    func() bool
	dpkgInstall func(deb string) error
	aptInstall  func(version string) error
	restoreDB   func(backup string) error
	holdPkg     func() error
	now         func() time.Time
}

func (r *rollbackExec) run(intent *rollbackIntent, attempts int) rollbackOutcome {
	out := rollbackOutcome{ToVersion: intent.ToVersion, FromVersion: intent.FromVersion,
		Reasons: intent.Reasons, At: r.now(), Attempts: attempts}

	if err := r.units.stop(panelService); err != nil {
		log.Printf("rollback: stop panel: %v", err)
	}
	if err := r.units.mask(panelService); err != nil {
		log.Printf("rollback: mask panel: %v", err)
	}

	if r.installed() != intent.ToVersion {
		if !r.waitLockFree() {
			log.Printf("rollback: dpkg busy, deferred")
			out.Kind = outcomeDeferred
			return out
		}
		if err := r.installTarget(intent); err != nil {
			if errors.Is(err, errDpkgBusy) {
				log.Printf("rollback: dpkg busy, deferred")
				out.Kind = outcomeDeferred
				return out
			}
			log.Printf("rollback: install target: %v", err)
			out.Kind = "limp"
			return out
		}
	}

	if err := r.restoreDB(intent.DBBackup); err != nil {
		log.Printf("rollback: restore db: %v", err)
	}

	if err := r.holdPkg(); err != nil {
		log.Printf("rollback: hold: %v", err)
	}

	if err := r.units.unmask(panelService); err != nil {
		log.Printf("rollback: unmask panel: %v", err)
	}
	if err := r.units.start(panelService); err != nil {
		log.Printf("rollback: start panel: %v", err)
	}

	out.Kind = "rolled_back"
	return out
}

func (r *rollbackExec) waitLockFree() bool {
	if r.lockFree == nil {
		return true
	}
	bound, step := time.Minute, 2*time.Second
	if st, err := r.units.state(panelService); err == nil {
		if st.Window > bound {
			bound = st.Window
		}
		if st.Pause > step {
			step = st.Pause
		}
	}
	deadline := r.now().Add(bound)
	for !r.lockFree() {
		if r.now().After(deadline) {
			return false
		}
		r.units.wait(step)
	}
	return true
}

func (r *rollbackExec) installTarget(intent *rollbackIntent) error {
	if intent.DebPath != "" && fileExists(intent.DebPath) {
		return r.dpkgInstall(intent.DebPath)
	}
	return r.aptInstall(intent.ToVersion)
}

func runRollback() int {
	intent := readRollbackIntent()
	if intent == nil {

		if !anyFailedStably(rollbackUnits) {
			return 0
		}
		if out := readOutcome(); out != nil {

			if out.Kind == "limp" {
				return 0
			}

			if out.Kind == "rolled_back" && installedVersion() == out.ToVersion {
				writeOutcome(rollbackOutcome{Kind: "limp", ToVersion: out.ToVersion, FromVersion: out.FromVersion,
					Reasons: append(out.Reasons, "прежняя версия после отката тоже не держится запущенной"),
					At:      time.Now(), Attempts: out.Attempts})
				log.Printf("rollback: anchor %s also fails after rollback (limp)", out.ToVersion)
				return 1
			}
		}
		intent = synthFromGood()
		if intent == nil {

			reviveFailed(rollbackUnits)
			return 0
		}

		if err := writeRollbackIntent(intent); err != nil {
			log.Printf("rollback: intent not written: %v", err)
			return 1
		}
	}
	prev := readOutcome()
	attempts := 1
	if prev != nil {
		attempts = prev.Attempts + 1
	}
	if attempts > rollbackMaxAttempts {

		writeOutcome(rollbackOutcome{Kind: "limp", ToVersion: intent.ToVersion,
			Reasons: intent.Reasons, At: time.Now(), Attempts: attempts})
		_ = durable.Remove(rollbackIntentFile)
		log.Printf("rollback: giving up after %d attempts (limp)", attempts)
		return 1
	}

	if pol, ok := loadStoredPolicy(); ok && !versionAllowed(intent.ToVersion, pol, dpkgCompare) {
		writeOutcome(rollbackOutcome{Kind: "limp", ToVersion: intent.ToVersion,
			Reasons: append(intent.Reasons, "цель отката запрещена политикой: плохая версия или ниже пола"),
			At:      time.Now(), Attempts: attempts})
		_ = durable.Remove(rollbackIntentFile)
		log.Printf("rollback: target %s forbidden by policy (limp)", intent.ToVersion)
		return 1
	}

	out := newRollbackExec().run(intent, attempts)
	if out.Kind == outcomeDeferred {

		return 1
	}
	writeOutcome(out)
	if out.Kind == "rolled_back" {

		_ = durable.Remove(rollbackIntentFile)
		log.Printf("rollback: done, back on %s", intent.ToVersion)
		return 0
	}
	return 1
}

var newRollbackExec = func() *rollbackExec {
	return &rollbackExec{
		installed:   installedVersion,
		units:       rollbackUnits,
		lockFree:    dpkgLockFree,
		dpkgInstall: dpkgInstall,
		aptInstall:  aptInstallVersion,
		restoreDB:   restoreBackup,
		holdPkg:     func() error { return aptMarkHold("vpn-panel") },
		now:         time.Now,
	}
}

func versionAllowed(version string, pol policy.Policy, cmp func(a, op, b string) bool) bool {
	for _, bad := range pol.KnownBad() {
		if bad == version {
			return false
		}
	}
	if f := pol.Floor(); f != "" && !cmp(version, "ge", f) {
		return false
	}
	return true
}

func loadStoredPolicy() (policy.Policy, bool) {
	data, err := os.ReadFile(policyStatePath) //nolint:gosec
	if err != nil {
		return policy.Default(), false
	}
	p, _, perr := policy.Parse(data)
	if perr != nil {
		return policy.Default(), false
	}
	return p, true
}

func synthFromGood() *rollbackIntent {
	good := readReleaseGood()
	running := installedVersion()
	if good == nil || running == good.Version {
		return nil
	}
	return &rollbackIntent{
		ToVersion:   good.Version,
		FromVersion: running,
		DebPath:     good.DebPath,
		DBBackup:    newestBackup(),
		Reasons:     []string{"служба не поднимается после обновления"},
		CreatedAt:   time.Now(),
	}
}

var watchedUnits = []string{panelService, agentUnit}

func anyFailedStably(ops *unitOps) bool {
	for _, u := range watchedUnits {
		if failedStably(ops, u) {
			return true
		}
	}
	return false
}

func reviveFailed(ops *unitOps) {
	for _, u := range watchedUnits {
		st, err := ops.state(u)
		if err != nil || !st.failed() {
			continue
		}
		if err := ops.resetFailed(u); err != nil {
			log.Printf("rollback: reset-failed %s: %v", u, err)
		}
		if err := ops.start(u); err != nil {
			log.Printf("rollback: start %s: %v", u, err)
		}
		log.Printf("rollback: %s restarted after start limit, nothing to roll back", u)
	}
}

var dpkgFrontendLock = "/var/lib/dpkg/lock-frontend"

func dpkgLockFree() bool {
	f, err := os.Open(dpkgFrontendLock) //nolint:gosec
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
		return true
	}
	return lk.Type == syscall.F_UNLCK
}

func dpkgInstall(deb string) error {
	bin, err := findBinary(dpkgCandidates)
	if err != nil {
		return err
	}
	out, cerr := exec.Command(bin, "-i", deb).CombinedOutput() //nolint:gosec
	if cerr != nil {
		if !dpkgLockFree() {
			return errDpkgBusy
		}
		return fmt.Errorf("%s: %s", cerr, firstLine(out))
	}
	return nil
}

func aptInstallVersion(version string) error {
	bin, err := findBinary(aptGetCandidates)
	if err != nil {
		return err
	}

	pkg := "vpn-panel=" + version
	out, cerr := exec.Command(bin, "-y", "--allow-downgrades", "install", pkg).CombinedOutput() //nolint:gosec
	if cerr != nil {
		return fmt.Errorf("%s: %s", cerr, firstLine(out))
	}
	return nil
}

func aptMarkHold(pkg string) error {
	bin, err := findBinary(aptMarkCandidates)
	if err != nil {
		return err
	}
	out, cerr := exec.Command(bin, "hold", pkg).CombinedOutput() //nolint:gosec
	if cerr != nil {
		return fmt.Errorf("%s: %s", cerr, firstLine(out))
	}
	return nil
}

func newestBackup() string {
	backs, _ := filepath.Glob(panelDBPath + ".bak-*")
	if len(backs) == 0 {
		return ""
	}
	sort.Strings(backs)
	return backs[len(backs)-1]
}

func restoreBackup(backup string) error {
	if backup == "" || !fileExists(backup) {
		backup = newestBackup()
	}
	if backup == "" {
		return fmt.Errorf("резервной копии базы нет")
	}
	data, err := os.ReadFile(backup) //nolint:gosec
	if err != nil {
		return err
	}
	if err := durable.Write(panelDBPath, data, 0o640); err != nil {
		return err
	}
	_ = durable.Remove(panelDBPath + "-wal")
	_ = durable.Remove(panelDBPath + "-shm")

	chownToPanel(panelDBPath)
	return nil
}

func writeOutcome(o rollbackOutcome) {
	data, err := json.Marshal(o)
	if err != nil {
		log.Printf("rollback: outcome not marshaled: %v", err)
		return
	}
	if err := durable.Write(rollbackOutcomeFile, append(data, '\n'), 0o600); err != nil {
		log.Printf("rollback: outcome not written: %v", err)
	}
}

func readOutcome() *rollbackOutcome {
	data, err := os.ReadFile(rollbackOutcomeFile) //nolint:gosec
	if err != nil {
		return nil
	}
	var o rollbackOutcome
	if json.Unmarshal(data, &o) != nil || o.Kind == "" {
		return nil
	}
	return &o
}

func chownToPanel(path string) {
	u, uerr := user.Lookup("vpn-admin")
	g, gerr := user.LookupGroup("vpn-panel")
	if uerr != nil || gerr != nil {
		return
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(g.Gid)
	if e1 != nil || e2 != nil {
		return
	}
	if err := os.Chown(path, uid, gid); err != nil { //nolint:gosec
		log.Printf("rollback: chown db: %v", err)
	}
}
