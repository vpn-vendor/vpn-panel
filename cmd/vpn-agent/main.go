package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/logdedup"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

const agentVersion = "0.1.0-dev"

const defaultSocketPath = "/run/vpn-panel/broker.sock"

func main() {
	log.SetPrefix("vpn-agent: ")

	log.SetFlags(0)
	log.SetOutput(logdedup.New(os.Stderr))

	if len(os.Args) > 1 {

		if os.Args[1] == "disk-change" {
			os.Exit(runDiskChange())
		}
		if os.Args[1] == "disk-setup" {
			os.Exit(runDiskSetup())
		}
		if os.Args[1] == "backup-code" {
			os.Exit(runBackupCode())
		}
		if os.Args[1] == "support" {
			os.Exit(runSupport())
		}
		if os.Args[1] == "console" {
			os.Exit(runConsole(os.Args[2:]))
		}
		runHookCommand(os.Args[1])
		return
	}

	socketPath, err := sanitizeSocketPath(os.Getenv("AGENT_SOCKET"))
	if err != nil {
		log.Fatalf("AGENT_SOCKET: %v", err)
	}

	listener, err := listen(socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	applySocketPermissions(socketPath)

	sweepLeftovers()

	composer := newModeComposer()
	composer.load()

	firewall := newFirewallApplier()
	firewall.composer = composer
	composer.onFirewallFacts = firewall.writeLockdown

	if facts, ok := composer.FirewallFacts(); ok {
		firewall.writeLockdown(facts)
	}
	firewall.restoreOnStart()
	applier := newNetplanApplier(firewall)
	applier.recoverAfterCrash()
	dns := newDNSApplier()
	dns.composer = composer
	dhcp := newDhcpApplier()
	dhcp.RestoreOnStart()
	go dhcp.WatchLink()
	qos := newQosApplier()
	qos.composer = composer
	qos.RestoreOnStart()
	diag := newDiagApplier()
	vpn := newVPNApplier(firewall, dns, qos)
	vpn.composer = composer
	firewall.intentBroken = func() bool { return vpn.readState().Broken }
	composer.onUnbound = func() { vpn.markServicesPending(true); vpn.kickWatchdog() }

	applier.onPathChanged = vpn.onPathChanged
	vpn.RestoreOnStart()
	clock := newTimeApplier()
	updates := newUpdatesApplier()
	logs := newLogsApplier()
	disk := newDiskApplier()
	backup := newBackupApplier(vpn)
	support := newSupportApplier(firewall, qos, vpn, updates, disk)
	support.leases = dhcp.activeLeases

	if devmode.Enabled {
		log.Printf("режим разработки (тег сборки dev): системные методы отвечают отказом, чтение работает")
	}
	server := agentMethods(applier, firewall, dns, dhcp, qos, diag, vpn, clock, updates, logs, disk, backup, support, newPanelApplier())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-stop
		log.Printf("received %s, shutting down", sig)

		vpn.StopWatchdog()
		_ = listener.Close()
	}()

	//nolint:gosec
	log.Printf("listening on %q (version %s)", socketPath, agentVersion)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("serve: %v", err)
	}
	_ = os.Remove(socketPath) //nolint:gosec
	log.Printf("stopped")
}

func runHookCommand(cmd string) {
	var method string
	switch cmd {
	case "wan-up":

		method = "qos.wan_up"
	default:

		log.Fatal("unknown command; supported: wan-up, disk-setup, disk-change, backup-code, support")
	}
	socketPath, err := sanitizeSocketPath(os.Getenv("AGENT_SOCKET"))
	if err != nil {
		log.Fatalf("AGENT_SOCKET: %v", err)
	}
	client := &agentrpc.Client{SocketPath: socketPath}
	resp, err := client.Call(method, map[string]any{})
	if err != nil {
		log.Fatalf("%s: %v", method, err)
	}
	if resp.Error != nil {
		log.Fatalf("%s: %s", method, resp.Error.Message)
	}
}

func runBackupCode() int {
	socketPath, err := sanitizeSocketPath(os.Getenv("AGENT_SOCKET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Служба панели настроена неверно — обратитесь в поддержку.")
		return 1
	}
	resp, err := (&agentrpc.Client{SocketPath: socketPath}).Call("backup.code", map[string]any{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Служба панели не отвечает — перезагрузите шлюз и повторите.")
		return 1
	}
	if resp.Error != nil {
		fmt.Fprintln(os.Stderr, "Код не выдан: "+resp.Error.Message+".")
		return 1
	}
	var r struct {
		Code      string `json:"code"`
		ExpiresIn int    `json:"expires_in_sec"`
	}
	if json.Unmarshal(resp.Result, &r) != nil || r.Code == "" {
		fmt.Fprintln(os.Stderr, "Код не выдан: служба ответила неожиданно — обратитесь в поддержку.")
		return 1
	}
	fmt.Printf("Код для выгрузки копии настроек: %s\n", r.Code)
	fmt.Printf("Введите его в браузере на странице «Резервная копия». Код действует %d минут и срабатывает один раз.\n", r.ExpiresIn/60)
	return 0
}

func sanitizeSocketPath(raw string) (string, error) {
	if raw == "" {
		return defaultSocketPath, nil
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("path contains control characters")
		}
	}
	return filepath.Clean(raw), nil
}

func listen(socketPath string) (net.Listener, error) {
	//nolint:gosec
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	if info, err := os.Lstat(socketPath); err == nil { //nolint:gosec
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket; refusing to remove", socketPath)
		}
		if err := os.Remove(socketPath); err != nil { //nolint:gosec
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return net.Listen("unix", socketPath)
}

func applySocketPermissions(socketPath string) {

	//nolint:gosec
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Printf("chmod socket: %v", err)
	}
	panelUser, uerr := user.Lookup("vpn-admin")
	panelGroup, gerr := user.LookupGroup("vpn-panel")
	if uerr != nil || gerr != nil {
		log.Printf("socket ownership skipped (DEV mode: vpn-admin/vpn-panel not present)")
		return
	}
	uid, err := strconv.Atoi(panelUser.Uid)
	if err != nil {
		log.Printf("bad uid for vpn-admin: %v", err)
		return
	}
	gid, err := strconv.Atoi(panelGroup.Gid)
	if err != nil {
		log.Printf("bad gid for vpn-panel: %v", err)
		return
	}
	if err := os.Chown(socketPath, uid, gid); err != nil { //nolint:gosec

		log.Printf("chown socket: %v", err)
	}
}

const CodeDevMode = 1900

func devGate(h agentrpc.Handler) agentrpc.Handler {
	if !devmode.Enabled {
		return h
	}
	return func(json.RawMessage) (any, *agentrpc.ErrorObject) {
		return nil, &agentrpc.ErrorObject{Code: CodeDevMode,
			Message: "Это среда разработки интерфейса: сеть, файрвол и службы здесь не применяются — системные функции проверяются на установленном шлюзе.",
			Data:    map[string]any{"recoverable": false}}
	}
}

func systemPing(json.RawMessage) (any, *agentrpc.ErrorObject) {
	return map[string]any{
		"pong":          true,
		"agent_version": agentVersion,
	}, nil
}

func networkStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	status, err := netstatus.Collect()
	if err != nil {
		log.Printf("network.status: %v", err)
		return nil, internalErr(errReadInterfaces, true)
	}
	return status, nil
}
