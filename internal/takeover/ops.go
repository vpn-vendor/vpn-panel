package takeover

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type OpKind string

const (
	OpStop    OpKind = "stop"
	OpStart   OpKind = "start"
	OpDisable OpKind = "disable"
	OpMask    OpKind = "mask"

	OpAside OpKind = "aside"

	OpBackup OpKind = "backup"

	OpDropLines OpKind = "drop_lines"

	OpCommentKeys OpKind = "comment_keys"

	OpSetKey OpKind = "set_key"

	OpSudoers OpKind = "sudoers"

	OpChownRoot OpKind = "chown_root"

	OpForwardAccept OpKind = "forward_accept"

	OpForwardPrune OpKind = "forward_prune"

	OpForwardPolicy OpKind = "forward_policy"

	OpExec OpKind = "exec"

	OpWaitGone OpKind = "wait_gone"

	OpStub OpKind = "stub"
)

const (
	CmdPoff = "poff dsl-provider"

	CmdPon          = "pon dsl-provider"
	CmdUdevReload   = "udevadm-reload"
	CmdDaemonReload = "daemon-reload"
)

func Kinds() []OpKind {
	return []OpKind{OpStop, OpStart, OpDisable, OpMask, OpAside, OpBackup, OpDropLines, OpCommentKeys,
		OpSetKey, OpSudoers, OpChownRoot, OpForwardAccept, OpForwardPrune, OpForwardPolicy, OpExec, OpWaitGone, OpStub}
}

func KnownCommand(c string) bool {
	return slices.Contains([]string{CmdPoff, CmdPon, CmdUdevReload, CmdDaemonReload}, c)
}

type Op struct {
	Kind    OpKind `json:"kind"`
	Unit    string `json:"unit,omitempty"`
	Path    string `json:"path,omitempty"`
	Family  string `json:"family,omitempty"`
	Table   string `json:"table,omitempty"`
	Chain   string `json:"chain,omitempty"`
	Command string `json:"command,omitempty"`

	Argv0 string   `json:"argv0,omitempty"`
	Args  []string `json:"args,omitempty"`
	Lines []string `json:"lines,omitempty"`
	Keys  []string `json:"keys,omitempty"`

	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`

	Mode uint32 `json:"mode,omitempty"`
}

func (op Op) temporary() bool {
	switch op.Kind {
	case OpStop, OpStart, OpWaitGone:
		return true
	case OpExec:
		return op.Command == CmdPoff || op.Command == CmdPon
	}
	return false
}

func (op Op) Matches(cmdline []byte) bool {
	argv := strings.Split(string(cmdline), "\x00")
	if n := len(argv); n > 0 && argv[n-1] == "" {
		argv = argv[:n-1]
	}
	return len(argv) > 0 && filepath.Base(argv[0]) == op.Argv0 && slices.Equal(argv[1:], op.Args)
}

func (op Op) Valid() error {
	bad := func(what string) error { return fmt.Errorf("операция %q: %s", op.Kind, what) }
	switch op.Kind {
	case OpStop, OpStart, OpDisable, OpMask:
		if !validUnit(op.Unit) {
			return bad("негодное имя юнита")
		}
	case OpAside, OpBackup, OpStub, OpChownRoot:
		if !absPath(op.Path) {
			return bad("путь не абсолютный")
		}
	case OpDropLines, OpSudoers:
		if !absPath(op.Path) || len(op.Lines) == 0 {
			return bad("нет пути или строк")
		}
	case OpCommentKeys:
		if !absPath(op.Path) || len(op.Keys) == 0 {
			return bad("нет пути или ключей")
		}
	case OpSetKey:
		if !absPath(op.Path) || !shellName(op.Key) || strings.ContainsAny(op.Value, "\"\\$`\n") {
			return bad("негодный ключ или значение")
		}
	case OpForwardAccept, OpForwardPrune:
		if !forwardFamilies[op.Family] || op.Table == "" || op.Chain == "" {
			return bad("нет цепочки")
		}
	case OpForwardPolicy:
		all := op.Family == "" && op.Table == "" && op.Chain == ""
		if !all && (!forwardFamilies[op.Family] || op.Table == "" || op.Chain == "") {
			return bad("цепочка задана не полностью")
		}
	case OpExec:
		if !KnownCommand(op.Command) {
			return bad("команды нет в перечне")
		}
	case OpWaitGone:
		if op.Argv0 == "" || strings.Contains(op.Argv0, "/") {
			return bad("нет имени процесса")
		}
	default:
		return errors.New("незнакомая операция " + string(op.Kind))
	}
	return nil
}

func absPath(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

var forwardFamilies = map[string]bool{"ip": true, "ip6": true, "inet": true}

var (
	keepChainPrefixes = []string{"DOCKER", "LIBVIRT_"}
	keepIfacePrefixes = []string{"docker", "virbr"}

	dockerBridge = regexp.MustCompile(`^br-[0-9a-f]{12}$`)
)

func KeepInForward(jumps, ifaces []string) bool {
	prefixed := func(names, prefixes []string) bool {
		for _, n := range names {
			for _, p := range prefixes {
				if strings.HasPrefix(n, p) {
					return true
				}
			}
		}
		return false
	}
	return prefixed(jumps, keepChainPrefixes) || prefixed(ifaces, keepIfacePrefixes) ||
		slices.ContainsFunc(ifaces, dockerBridge.MatchString)
}

func shellName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, r := range s {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func shellAssign(line, key string) (string, bool) {
	t := strings.TrimSpace(line)
	if rest, ok := strings.CutPrefix(t, "export "); ok {
		t = strings.TrimSpace(rest)
	}
	v, ok := strings.CutPrefix(t, key+"=")
	if !ok {
		return "", false
	}
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return v, true
}

func shellValue(data []byte, key string) (string, bool) {
	val, found := "", false
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := shellAssign(line, key); ok {
			val, found = v, true
		}
	}
	return val, found
}

func SetShellKey(data []byte, key, value string) []byte {
	want := key + `="` + value + `"`
	lines := strings.Split(string(data), "\n")
	set := false
	for i, line := range lines {
		if _, ok := shellAssign(line, key); ok {
			lines[i], set = want, true
		}
	}
	out := []byte(strings.Join(lines, "\n"))
	if set {
		return out
	}
	if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	return append(out, want+"\n"...)
}
