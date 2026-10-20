package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
)

var (
	keaCandidates     = []string{"/usr/sbin/kea-dhcp4", "/sbin/kea-dhcp4"}
	netplanCandidates = []string{"/usr/sbin/netplan", "/sbin/netplan"}
	setprivCandidates = []string{"/usr/bin/setpriv", "/bin/setpriv"}
)

func hostProbeSet() []hostProbe {
	return []hostProbe{
		{ids: append([]string{"nft.ruleset"}, hostcaps.IDs(nftgen.Options)...), packages: []string{"nftables"}, run: probeNft},
		{ids: hostcaps.IDs(keagen.Options), packages: []string{"kea-dhcp4-server"}, run: probeKea},
		kernelProbe("kernel.cake", hostcaps.ClassComfort, []string{"qos"}, "Очередь CAKE в ядре",
			"В ядре нет модулей очереди CAKE: QoS недоступен. Интернет и защита работают.", "sch_cake", "ifb"),
		{ids: []string{"netplan.try"}, packages: []string{"netplan.io"}, run: probeNetplanTry},
		{ids: []string{factPPPNotify, factPPPPlugin}, packages: []string{"ppp"}, run: probePPP},
		{ids: []string{"os.codename"}, run: probeCodename},
	}
}

func kernelProbe(id string, class hostcaps.Class, consumers []string, title, missing string,
	modules ...string) hostProbe {
	return hostProbe{ids: []string{id}, run: func(ctx context.Context) []hostcaps.Fact {
		f := hostcaps.Fact{ID: id, Class: class, Answer: hostcaps.Unknown, How: hostcaps.HowFailed, Consumers: consumers,
			Title: title, Missing: missing}
		if modprobe, err := findBinary(modprobeCandidates); err == nil {
			f.Answer, f.How = modulesAvailable(ctx, modprobe, modules), hostcaps.HowModprobe
		}
		return []hostcaps.Fact{f}
	}}
}

func probeNft(ctx context.Context) []hostcaps.Fact {
	return hostcaps.Probe(hostcaps.Program[nftgen.Caps]{
		Render:        func(c nftgen.Caps) ([]byte, error) { return nftgen.ProbeRuleset(c), nil },
		Check:         func(b []byte) error { return checkNftIsolated(ctx, b) },
		Spoil:         appendLine("vp-probe-unknown-statement"),
		Base:          "nft.ruleset",
		BaseClass:     hostcaps.ClassGuard,
		BaseConsumers: []string{"network"},
		BaseTitle:     "Правила фаервола в ядре",
		BaseMissing: "Ядро или nftables этой системы не принимают правила панели: раздача интернета и защита не " +
			"включатся. Обновите систему или поставьте шлюз с флешки.",
		Options: nftgen.Options,
	})
}

func probeKea(ctx context.Context) []hostcaps.Fact {
	lans := keagen.ProbePlan().LANs
	return hostcaps.Probe(hostcaps.Program[keagen.Caps]{
		Render: func(c keagen.Caps) ([]byte, error) {
			p := keagen.ProbePlan()
			return p.Generate(c)
		},
		Check:   func(b []byte) error { return checkKeaIsolated(ctx, lans, b) },
		Spoil:   spoilKea,
		Options: keagen.Options,
	})
}

func modulesAvailable(ctx context.Context, modprobe string, modules []string) hostcaps.Answer {
	for _, m := range modules {
		err := exec.CommandContext(ctx, modprobe, "--dry-run", "--quiet", m).Run() //nolint:gosec
		if err == nil {
			continue
		}
		var exit *exec.ExitError
		if ctx.Err() == nil && errors.As(err, &exit) {
			return hostcaps.No
		}
		return hostcaps.Unknown
	}
	return hostcaps.Yes
}

func probeNetplanTry(ctx context.Context) []hostcaps.Fact {
	f := hostcaps.Fact{ID: "netplan.try", Class: hostcaps.ClassGuard, Answer: hostcaps.No, How: hostcaps.HowRun,
		Consumers: []string{"network"}, Title: "Применение сети с откатом",
		Missing: "В системе нет Netplan с откатом изменений: панель не может безопасно менять сеть. " +
			"Поставьте шлюз с флешки или обратитесь в поддержку."}
	bin, err := findBinary(netplanCandidates)
	if err != nil {
		return []hostcaps.Fact{f}
	}
	err = exec.CommandContext(ctx, bin, "try", "--help").Run() //nolint:gosec
	var exit *exec.ExitError
	switch {
	case err == nil:
		f.Answer = hostcaps.Yes
	case ctx.Err() != nil || !errors.As(err, &exit):
		f.Answer, f.How = hostcaps.Unknown, hostcaps.HowFailed
	}
	return []hostcaps.Fact{f}
}

const (
	factPPPNotify = "ppp.notify"
	factPPPPlugin = "ppp.plugin"
	consumerPPPoE = "pppoe"
)

var (
	pppdCandidates = []string{"/usr/sbin/pppd"}

	pppoePluginGlob = "/usr/lib/pppd/*/pppoe.so"

	libSystemd = "libsystemd.so"
)

func probePPP(context.Context) []hostcaps.Fact {
	notify := hostcaps.Fact{ID: factPPPNotify, Class: hostcaps.ClassGuard, Answer: hostcaps.No, How: hostcaps.HowFile,
		Consumers: []string{consumerPPPoE}, Title: "Подключение PPPoE под надзором системы",
		Missing: "Программа подключения по логину и паролю в этой системе не умеет сообщать о готовности: подключение PPPoE панель не поднимет. Обновите систему или подключайтесь через роутер провайдера."}
	plugin := hostcaps.Fact{ID: factPPPPlugin, Class: hostcaps.ClassGuard, Answer: hostcaps.No, How: hostcaps.HowFile,
		Consumers: []string{consumerPPPoE}, Title: "Модуль PPPoE",
		Missing: "В системе нет модуля PPPoE для программы подключения: подключение по логину и паролю панель не поднимет. Обновите систему или подключайтесь через роутер провайдера."}
	if bin, err := findBinary(pppdCandidates); err == nil {
		notify.Answer = pppdNotifies(bin)
	}
	if m, err := filepath.Glob(pppoePluginGlob); err == nil && len(m) > 0 {
		plugin.Answer = hostcaps.Yes
	}
	return []hostcaps.Fact{notify, plugin}
}

func pppdNotifies(bin string) hostcaps.Answer {
	f, err := elf.Open(bin)
	if err != nil {
		return hostcaps.Unknown
	}
	defer func() { _ = f.Close() }()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return hostcaps.Unknown
	}
	for _, l := range libs {
		if strings.HasPrefix(l, libSystemd) {
			return hostcaps.Yes
		}
	}
	return hostcaps.No
}

func probeCodename(context.Context) []hostcaps.Fact {
	f := hostcaps.Fact{ID: "os.codename", Class: hostcaps.ClassDecision, Answer: hostcaps.Unknown,
		How: hostcaps.HowFile, Consumers: []string{"updates"}, Title: "Выпуск системы",
		Missing: "Не удалось прочитать выпуск системы: источник обновлений не настроен. Обратитесь в поддержку."}
	if v := osCodename(); v != "" {
		f.Answer, f.Value = hostcaps.Yes, v
	}
	return []hostcaps.Fact{f}
}

func checkKeaIsolated(ctx context.Context, lans []keagen.LAN, cfg []byte) error {
	kea, err := findBinary(keaCandidates)
	if err != nil {
		return err
	}
	if err := durable.MkdirAll(keaConfigDir, 0o750); err != nil {
		return err
	}
	chownDirForKea(keaConfigDir)
	staged, err := durable.Stage(keaConfigFile, cfg, 0o640, keaOwner()...)
	if err != nil {
		return err
	}
	defer staged.Abort()
	ifaces := make([]isolatedIface, 0, len(lans))
	for _, l := range lans {
		ifaces = append(ifaces, isolatedIface{name: l.Name, cidr: l.CIDR})
	}
	out, err := runIsolated(ctx, ifaces, keaCredential(), nil, kea, "-t", staged.Path())
	return verdict(ctx, out, err)
}

func checkNftIsolated(ctx context.Context, ruleset []byte) error {
	nft, err := findBinary(nftCandidates)
	if err != nil {
		return err
	}
	out, err := runIsolated(ctx, nil, nil, ruleset, nft, "-c", "-f", "-")
	return verdict(ctx, out, err)
}

type isolatedIface struct{ name, cidr string }

const isolatedSetupFailed = 97

var errIsolatedSetup = errors.New("пробные карты не созданы")

const isolatedScript = `ip="$1"; setpriv="$2"; uid="$3"; gid="$4"; n="$5"; shift 5
while [ "$n" -gt 0 ]; do
	"$ip" link add "$1" type dummy || exit 97
	"$ip" addr add "$2" dev "$1" || exit 97
	"$ip" link set "$1" up || exit 97
	shift 2
	n=$((n - 1))
done
if [ -n "$uid" ]; then
	exec "$setpriv" --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
fi
exec "$@"`

func runIsolated(ctx context.Context, ifaces []isolatedIface, cred *syscall.Credential, stdin []byte,
	bin string, args ...string) ([]byte, error) {
	var cmd *exec.Cmd
	if len(ifaces) == 0 && cred == nil {
		cmd = exec.CommandContext(ctx, bin, args...) //nolint:gosec
	} else {
		ip, err := findBinary(ipCandidates)
		if err != nil {
			return nil, err
		}
		argv := []string{"-c", isolatedScript, "sh", ip, "", "", "", strconv.Itoa(len(ifaces))}
		if cred != nil {
			setpriv, err := findBinary(setprivCandidates)
			if err != nil {
				return nil, err
			}
			argv[4], argv[5], argv[6] = setpriv,
				strconv.FormatUint(uint64(cred.Uid), 10), strconv.FormatUint(uint64(cred.Gid), 10)
		}
		for _, i := range ifaces {
			argv = append(argv, i.name, i.cidr)
		}
		argv = append(append(argv, bin), args...)
		cmd = exec.CommandContext(ctx, "/bin/sh", argv...) //nolint:gosec
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == isolatedSetupFailed {
		return out, errIsolatedSetup
	}
	return out, err
}

func verdict(ctx context.Context, out []byte, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return &hostcaps.Rejected{Detail: firstLine(out)}
	}
	return err
}

func appendLine(line string) func([]byte) []byte {
	return func(b []byte) []byte {
		out := append([]byte(nil), b...)
		return append(append(out, line...), '\n')
	}
}

func spoilKea(b []byte) []byte {
	var cfg map[string]map[string]any
	if json.Unmarshal(b, &cfg) != nil || cfg["Dhcp4"] == nil {
		return append(append([]byte(nil), b...), '{')
	}
	cfg["Dhcp4"]["vp-probe-unknown-key"] = 1
	out, err := json.Marshal(cfg)
	if err != nil {
		return append(append([]byte(nil), b...), '{')
	}
	return out
}
