package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
)

const (
	takeoverBackupPrefix = "takeover-"
	takeoverBackupStamp  = "20060102T150405Z"
	takeoverManifestName = "manifest.json"

	takeoverWaitGone = 15 * time.Second

	asideNameLen = 16
)

type takeoverCopy struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	SHA256 string `json:"sha256"`
}

type opHandler func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error

var opHandlers = map[takeover.OpKind]opHandler{
	takeover.OpStop: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error {
		return r.unitCmd("stop", op.Unit, true)
	},
	takeover.OpStart: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error {
		return r.unitCmd("start", op.Unit, false)
	},
	takeover.OpDisable: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error {
		return r.unitCmd("disable", op.Unit, true)
	},
	takeover.OpMask: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error {
		return r.sys.systemctl("mask", op.Unit)
	},
	takeover.OpAside:  func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error { return r.aside(j, op.Path) },
	takeover.OpBackup: func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error { return r.backup(j, op.Path) },
	takeover.OpDropLines: func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error {
		return r.editText(j, op.Path, dropLines(op.Lines), nil)
	},
	takeover.OpCommentKeys: func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error {
		return r.editText(j, op.Path, commentKeys(op.Keys), nil)
	},
	takeover.OpSetKey: func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error {
		return r.editText(j, op.Path, func(d []byte) []byte { return takeover.SetShellKey(d, op.Key, op.Value) }, nil)
	},
	takeover.OpSudoers: func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error {
		return r.editText(j, op.Path, dropLines(op.Lines), r.checkSudoers)
	},
	takeover.OpChownRoot: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error {
		return r.chownRoot(op.Path, op.Mode)
	},
	takeover.OpForwardAccept: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error { return r.forwardAccept(op) },
	takeover.OpForwardPrune:  func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error { return r.forwardPrune(op) },
	takeover.OpForwardPolicy: func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error { return r.forwardPolicy(op) },
	takeover.OpExec:          func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error { return r.command(op.Command) },
	takeover.OpWaitGone:      func(r *takeoverRunner, _ *takeover.Journal, op takeover.Op) error { return r.waitGone(op) },
	takeover.OpStub:          func(r *takeoverRunner, j *takeover.Journal, op takeover.Op) error { return r.stub(j, op.Path) },
}

func (r *takeoverRunner) do(j *takeover.Journal, p takeover.PendingOp) error {
	h, ok := opHandlers[p.Op.Kind]
	if !ok {
		return fmt.Errorf("незнакомая операция %q", p.Op.Kind)
	}
	return h(r, j, p.Op)
}

func (r *takeoverRunner) unitCmd(verb, unit string, skipMissing bool) error {
	if skipMissing {
		if states, ok := r.sys.units([]string{unit}); ok {
			if _, loaded := states[unit]; !loaded {
				return nil
			}
		}
	}
	return r.sys.systemctl(verb, unit)
}

func fileOwner(fi fs.FileInfo) (uid, gid int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func asideName(path string) string {
	return sha256Hex([]byte(path))[:asideNameLen] + "-" + filepath.Base(path)
}

func findAside(j *takeover.Journal, path string) (takeover.Aside, bool) {
	i := slices.IndexFunc(j.Aside, func(a takeover.Aside) bool { return a.Path == path })
	if i < 0 {
		return takeover.Aside{}, false
	}
	return j.Aside[i], true
}

func dropAside(j *takeover.Journal, path string) {
	j.Aside = slices.DeleteFunc(j.Aside, func(a takeover.Aside) bool { return a.Path == path })
}

func (r *takeoverRunner) aside(j *takeover.Journal, logical string) error {
	path := r.p(logical)
	if a, ok := findAside(j, logical); ok && fileExists(r.p(a.Saved)) {

		return durable.Remove(path)
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: не обычный файл", logical)
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return err
	}
	if err := durable.MkdirAll(r.p(r.asideDir), 0o700); err != nil {
		return err
	}
	uid, gid := fileOwner(fi)
	a := takeover.Aside{Path: logical, Saved: r.asideDir + "/" + asideName(logical),
		Mode: uint32(fi.Mode().Perm()), UID: uid, GID: gid}
	saved := r.p(a.Saved)
	if err := durable.Write(saved, data, fi.Mode().Perm(), durable.Owner(uid, gid)); err != nil {
		return err
	}
	dropAside(j, logical)
	j.Aside = append(j.Aside, a)
	if err := r.saveJournal(*j); err != nil {
		return err
	}
	return durable.Remove(path)
}

func (r *takeoverRunner) backup(j *takeover.Journal, logical string) error {
	src := r.p(logical)
	if a, ok := findAside(j, logical); ok && fileExists(r.p(a.Saved)) {
		src = r.p(a.Saved)
	}
	fi, err := os.Lstat(src)
	if errors.Is(err, fs.ErrNotExist) {
		dropAside(j, logical)
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: не обычный файл", logical)
	}
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		return err
	}
	if err := r.keepCopy(j, logical, data, fi); err != nil {
		return err
	}
	if err := durable.Remove(src); err != nil {
		return err
	}
	dropAside(j, logical)
	return nil
}

func (r *takeoverRunner) keepCopy(j *takeover.Journal, logical string, data []byte, fi fs.FileInfo) error {
	if j.Backup == "" {
		return errors.New("каталог резервной копии ещё не назначен")
	}
	uid, gid := fileOwner(fi)
	entry := takeoverCopy{Path: logical, Mode: uint32(fi.Mode().Perm()), UID: uid, GID: gid, SHA256: sha256Hex(data)}
	dup := r.p(j.Backup + logical)
	if cur, err := os.ReadFile(dup); err != nil || !bytes.Equal(cur, data) { //nolint:gosec
		if err := durable.MkdirAll(filepath.Dir(dup), 0o700); err != nil {
			return err
		}
		if err := durable.Write(dup, data, fi.Mode().Perm(), durable.Owner(uid, gid)); err != nil {
			return err
		}
	}
	return r.noteCopy(j, entry)
}

func (r *takeoverRunner) noteCopy(j *takeover.Journal, entry takeoverCopy) error {
	manifest := r.p(j.Backup + "/" + takeoverManifestName)
	var entries []takeoverCopy
	if cur, err := os.ReadFile(manifest); err == nil { //nolint:gosec
		_ = json.Unmarshal(cur, &entries)
	}
	entries = slices.DeleteFunc(entries, func(c takeoverCopy) bool { return c.Path == entry.Path })
	entries = append(entries, entry)
	slices.SortFunc(entries, func(a, b takeoverCopy) int { return strings.Compare(a.Path, b.Path) })
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return durable.Write(manifest, append(data, '\n'), 0o600)
}

func (r *takeoverRunner) editText(j *takeover.Journal, logical string, transform func([]byte) []byte, check func(staged string) error) error {
	path := r.p(logical)
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: не обычный файл", logical)
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return err
	}
	out := transform(data)
	if bytes.Equal(out, data) {
		return nil
	}
	if dup := r.p(j.Backup + logical); !fileExists(dup) {
		if err := r.keepCopy(j, logical, data, fi); err != nil {
			return err
		}
	}
	uid, gid := fileOwner(fi)
	st, err := durable.Stage(path, out, fi.Mode().Perm(), durable.Owner(uid, gid))
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(st.Path()); err != nil {
			st.Abort()
			return err
		}
	}
	return st.Commit()
}

func dropLines(lines []string) func([]byte) []byte {
	return func(data []byte) []byte {
		in := strings.Split(string(data), "\n")
		out := in[:0]
		for _, l := range in {
			if !slices.Contains(lines, strings.TrimSpace(l)) {
				out = append(out, l)
			}
		}
		return []byte(strings.Join(out, "\n"))
	}
}

func commentKeys(keys []string) func([]byte) []byte {
	return func(data []byte) []byte {
		lines := strings.Split(string(data), "\n")
		for i, l := range lines {
			t := strings.TrimPrefix(strings.TrimSpace(l), "-")
			if t == "" || t[0] == '#' || t[0] == ';' {
				continue
			}
			k, _, ok := strings.Cut(t, "=")
			if ok && slices.Contains(keys, strings.ReplaceAll(strings.TrimSpace(k), "/", ".")) {
				lines[i] = "#" + l
			}
		}
		return []byte(strings.Join(lines, "\n"))
	}
}

func (r *takeoverRunner) checkSudoers(staged string) error {
	out, code, err := r.sys.run("visudo", "-c", "-f", staged)
	if err != nil {
		return fmt.Errorf("visudo: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("visudo отверг новый sudoers: %s", firstLine(out))
	}
	return nil
}

func (r *takeoverRunner) chownRoot(logical string, mode uint32) error {
	top := r.p(logical)
	fi, err := os.Lstat(top)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: не каталог", logical)
	}
	err = filepath.WalkDir(top, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return r.sys.lchown(p, 0, 0)
	})
	if err != nil {
		return err
	}
	dirMode := fs.FileMode(mode)
	if mode == 0 {
		dirMode = fi.Mode().Perm() &^ 0o022
	}
	return r.sys.chmod(top, dirMode)
}

type nftChainSpec struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type nftRuleSpec struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Handle int               `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

type nftListing struct {
	Objects []struct {
		Chain *nftChainSpec `json:"chain"`
		Rule  *nftRuleSpec  `json:"rule"`
	} `json:"nftables"`
}

func parseNftListing(out []byte) (nftListing, error) {
	var l nftListing
	if err := json.Unmarshal(out, &l); err != nil {
		return l, fmt.Errorf("ответ nft не разобран: %w", err)
	}
	return l, nil
}

func nftMissing(out []byte) bool { return bytes.Contains(out, []byte("No such file or directory")) }

func (r *takeoverRunner) listChain(op takeover.Op) (chain nftChainSpec, rules []nftRuleSpec, found bool, err error) {
	if err := nftWords(op.Family, op.Table, op.Chain); err != nil {
		return nftChainSpec{}, nil, false, err
	}
	out, err := r.sys.nft(nil, "-j", "-a", "list", "chain", op.Family, op.Table, op.Chain)
	if err != nil {
		if nftMissing(out) {
			return nftChainSpec{}, nil, false, nil
		}
		return nftChainSpec{}, nil, false, fmt.Errorf("nft list chain: %s", firstLine(out))
	}
	l, err := parseNftListing(out)
	if err != nil {
		return nftChainSpec{}, nil, false, err
	}
	for _, o := range l.Objects {
		if o.Chain != nil && o.Chain.Family == op.Family && o.Chain.Table == op.Table && o.Chain.Name == op.Chain {
			chain, found = *o.Chain, true
		}
		if o.Rule != nil && o.Rule.Family == op.Family && o.Rule.Table == op.Table && o.Rule.Chain == op.Chain {
			rules = append(rules, *o.Rule)
		}
	}
	return chain, rules, found, nil
}

func nftWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-/", r)
		if !ok {
			return false
		}
	}
	return true
}

func nftWords(ss ...string) error {
	for _, s := range ss {
		if !nftWord(s) {
			return fmt.Errorf("имя %q не годится для nft", s)
		}
	}
	return nil
}

func policyAccept(c nftChainSpec) (string, error) {
	if c.Hook == "" {
		return "", nil
	}
	if err := nftWords(c.Family, c.Table, c.Name, c.Type, c.Hook); err != nil {
		return "", err
	}
	return fmt.Sprintf("add chain %s %s %s { type %s hook %s priority %d; policy accept; }\n",
		c.Family, c.Table, c.Name, c.Type, c.Hook, c.Prio), nil
}

func (r *takeoverRunner) nftApply(tx string) error {
	if tx == "" {
		return nil
	}
	if out, err := r.sys.nft([]byte(tx), "-f", "-"); err != nil {
		return fmt.Errorf("nft: %s", firstLine(out))
	}
	return nil
}

func (r *takeoverRunner) forwardAccept(op takeover.Op) error {
	c, _, found, err := r.listChain(op)
	if err != nil || !found {
		return err
	}
	policy, err := policyAccept(c)
	if err != nil {
		return err
	}
	return r.nftApply(fmt.Sprintf("flush chain %s %s %s\n", op.Family, op.Table, op.Chain) + policy)
}

func (r *takeoverRunner) forwardPrune(op takeover.Op) error {
	c, rules, found, err := r.listChain(op)
	if err != nil || !found {
		return err
	}
	var tx strings.Builder
	for _, rule := range rules {
		jumps, ifaces := ruleTargets(rule.Expr)
		if takeover.KeepInForward(jumps, ifaces) {
			continue
		}
		fmt.Fprintf(&tx, "delete rule %s %s %s handle %d\n", op.Family, op.Table, op.Chain, rule.Handle)
	}
	policy, err := policyAccept(c)
	if err != nil {
		return err
	}
	tx.WriteString(policy)
	return r.nftApply(tx.String())
}

func ruleTargets(exprs []json.RawMessage) (jumps, ifaces []string) {
	type target struct {
		Target string `json:"target"`
	}
	type match struct {
		Left struct {
			Meta struct {
				Key string `json:"key"`
			} `json:"meta"`
		} `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	for _, raw := range exprs {
		var e struct {
			Jump  *target `json:"jump"`
			Goto  *target `json:"goto"`
			Match *match  `json:"match"`
		}
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		for _, t := range []*target{e.Jump, e.Goto} {
			if t != nil && t.Target != "" {
				jumps = append(jumps, t.Target)
			}
		}
		if e.Match == nil || (e.Match.Left.Meta.Key != "iifname" && e.Match.Left.Meta.Key != "oifname") {
			continue
		}
		var one string
		if json.Unmarshal(e.Match.Right, &one) == nil {
			ifaces = append(ifaces, one)
			continue
		}
		var set struct {
			Set []string `json:"set"`
		}
		if json.Unmarshal(e.Match.Right, &set) == nil {
			ifaces = append(ifaces, set.Set...)
		}
	}
	return jumps, ifaces
}

func (r *takeoverRunner) forwardPolicy(op takeover.Op) error {
	if op.Chain != "" {
		c, _, found, err := r.listChain(op)
		if err != nil || !found {
			return err
		}
		policy, err := policyAccept(c)
		if err != nil {
			return err
		}
		return r.nftApply(policy)
	}
	out, err := r.sys.nft(nil, "-j", "-t", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("nft list ruleset: %s", firstLine(out))
	}
	l, err := parseNftListing(out)
	if err != nil {
		return err
	}
	skip := map[string]bool{}
	for _, t := range ownTables {
		skip[t] = true
	}
	for _, o := range l.Objects {
		if o.Chain != nil && takeover.KeepInForward([]string{o.Chain.Name}, nil) {
			skip[o.Chain.Family+" "+o.Chain.Table] = true
		}
	}
	var tx strings.Builder
	for _, o := range l.Objects {
		c := o.Chain
		if c == nil || c.Hook != "forward" || skip[c.Family+" "+c.Table] {
			continue
		}
		switch c.Family {
		case "ip", "ip6", "inet":
			policy, err := policyAccept(*c)
			if err != nil {
				return err
			}
			tx.WriteString(policy)
		}
	}
	return r.nftApply(tx.String())
}

func pppdWait() takeover.Op {
	return takeover.Op{Kind: takeover.OpWaitGone, Argv0: "pppd", Args: []string{"call", legacyvpn.PPPoECommand}}
}

func (r *takeoverRunner) pppdRunning() bool {
	op := pppdWait()
	return slices.ContainsFunc(r.sys.cmdlines(), op.Matches)
}

func (r *takeoverRunner) command(cmd string) error {
	switch cmd {
	case takeover.CmdPoff:

		out, code, err := r.sys.run("poff", legacyvpn.PPPoECommand)
		if err != nil {
			return fmt.Errorf("poff: %w", err)
		}
		if code != 0 && code != 1 {
			return fmt.Errorf("poff: %s", firstLine(out))
		}
	case takeover.CmdPon:

		if r.pppdRunning() {
			return nil
		}
		out, code, err := r.sys.run("pon", legacyvpn.PPPoECommand)
		if err != nil {
			return fmt.Errorf("pon: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("pon: %s", firstLine(out))
		}
	case takeover.CmdDaemonReload:
		return r.sys.systemctl("daemon-reload")
	case takeover.CmdUdevReload:
		out, code, err := r.sys.run("udevadm", "control", "--reload-rules")
		if err != nil {
			return fmt.Errorf("udevadm: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("udevadm: %s", firstLine(out))
		}
	default:
		return fmt.Errorf("команды %q нет в перечне", cmd)
	}
	return nil
}

func (r *takeoverRunner) waitGone(op takeover.Op) error {
	deadline := r.sys.now().Add(takeoverWaitGone)

	step := takeoverWaitGone / 50
	for {
		if !slices.ContainsFunc(r.sys.cmdlines(), op.Matches) {
			return nil
		}
		if !r.sys.now().Before(deadline) {
			return fmt.Errorf("процесс %s %s не завершился", op.Argv0, strings.Join(op.Args, " "))
		}
		r.sys.sleep(step)
	}
}

func (r *takeoverRunner) stub(j *takeover.Journal, logical string) error {
	if j.Backup == "" {
		return errors.New("каталог резервной копии ещё не назначен")
	}
	out, err := r.sys.home("stub", logical, j.Backup)
	if err != nil {
		return fmt.Errorf("заглушка %s: %w", logical, err)
	}
	var entry takeoverCopy
	if err := json.Unmarshal(out, &entry); err != nil {
		return fmt.Errorf("заглушка %s: ответ не разобран: %w", logical, err)
	}
	return r.noteCopy(j, entry)
}

var (
	systemctlCandidates  = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	systemdRunCandidates = []string{"/usr/bin/systemd-run", "/bin/systemd-run"}

	takeoverTools = map[string][]string{
		"poff":    {"/usr/bin/poff"},
		"pon":     {"/usr/bin/pon"},
		"udevadm": {"/usr/bin/udevadm", "/bin/udevadm"},
		"visudo":  {"/usr/sbin/visudo", "/sbin/visudo"},
	}
)

const agentBinary = "/usr/libexec/vpn-panel/vpn-agent"

func realTakeoverSys() takeoverSys {
	return takeoverSys{
		root:      "/",
		systemctl: systemctl,
		units:     takeoverUnitStates,
		nft: func(stdin []byte, args ...string) ([]byte, error) {
			bin, err := findBinary(nftCandidates)
			if err != nil {
				return nil, err
			}
			return runStdin(bin, stdin, args...)
		},
		run:      takeoverRunTool,
		cmdlines: procCmdlines,
		bootID:   readBootID,
		now:      time.Now,
		sleep:    time.Sleep,
		home:     legacyHomeOutside,
		cards: func() ([]netstatus.Interface, error) {
			st, err := netstatus.Collect()
			if err != nil {
				return nil, err
			}
			var out []netstatus.Interface
			for _, i := range st.Interfaces {
				if !i.Loopback {
					out = append(out, i)
				}
			}
			return out, nil
		},
		lchown: func(p string, uid, gid int) error { return os.Lchown(p, uid, gid) },
		chmod:  func(p string, mode os.FileMode) error { return os.Chmod(p, mode) },
		spawn:  func(f func()) { go f() },
	}
}

var takeoverUnitProps = []string{"Id", "LoadState", "UnitFileState", "ActiveState", "SubState", "FragmentPath"}

func takeoverUnitStates(names []string) (map[string]takeover.UnitState, bool) {
	bin, err := findBinary(systemctlCandidates)
	if err != nil {
		return nil, false
	}
	args := []string{"show"}
	for _, p := range takeoverUnitProps {
		args = append(args, "-p", p)
	}
	args = append(append(args, "--"), names...)
	out, err := exec.Command(bin, args...).Output() //nolint:gosec
	if err != nil {
		return nil, false
	}
	return parseTakeoverUnits("/", string(out)), true
}

func parseTakeoverUnits(root, out string) map[string]takeover.UnitState {
	res := map[string]takeover.UnitState{}
	for _, block := range strings.Split(out, "\n\n") {
		var id, load, fragment string
		var st takeover.UnitState
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			switch k {
			case "Id":
				id = v
			case "LoadState":
				load = v
			case "UnitFileState":
				st.Enabled = v == "enabled" || v == "enabled-runtime" || v == "generated"
				st.Masked = v == "masked" || v == "masked-runtime"
			case "ActiveState":
				st.Active = v == "active" || v == "activating" || v == "reloading"
			case "FragmentPath":
				fragment = v
			}
		}
		if id == "" || load == "" || load == "not-found" {
			continue
		}
		if strings.HasPrefix(fragment, legacyvpn.UnitDir+"/") {
			fi, err := os.Lstat(filepath.Join(root, fragment))
			st.FileInEtc = err == nil && fi.Mode().IsRegular()
		}
		res[id] = st
	}
	return res
}

func takeoverRunTool(tool string, args ...string) ([]byte, int, error) {
	candidates, ok := takeoverTools[tool]
	if !ok {
		return nil, 0, fmt.Errorf("инструмента %q нет в перечне", tool)
	}
	bin, err := findBinary(candidates)
	if err != nil {
		return nil, 0, err
	}
	out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out, exitErr.ExitCode(), nil
	}
	return out, 0, err
}

func procCmdlines() [][]byte {
	paths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	out := make([][]byte, 0, len(paths))
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 { //nolint:gosec
			out = append(out, data)
		}
	}
	return out
}

func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func legacyHomeOutside(args ...string) ([]byte, error) {
	bin, err := findBinary(systemdRunCandidates)
	if err != nil {
		return nil, err
	}
	argv := []string{"--wait", "--pipe", "--quiet", "--collect", "-p", "ProtectHome=no", agentBinary, "legacy-home"}
	argv = append(argv, args...)
	out, err := exec.Command(bin, argv...).Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("legacy-home %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
