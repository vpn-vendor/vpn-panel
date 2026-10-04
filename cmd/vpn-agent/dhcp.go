package main

import (
	"encoding/csv"
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

const (
	codeDHCPPlan   = 1202
	codeDHCPNoTool = 1203
	codeDHCPConfig = 1204
)

const (
	keaConfigDir   = "/etc/kea/vpn-panel"
	keaConfigFile  = "/etc/kea/vpn-panel/kea-dhcp4.conf"
	keaDropInDir   = "/etc/systemd/system/kea-dhcp4-server.service.d"
	keaDropInFile  = "/etc/systemd/system/kea-dhcp4-server.service.d/vpn-panel.conf"
	keaServiceName = "kea-dhcp4-server.service"
)

const keaDropIn = `[Unit]
StartLimitIntervalSec=0

[Service]
ExecStart=
ExecStart=/usr/sbin/kea-dhcp4 -c ` + keaConfigFile + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=15
`

const keaUser = "_kea"

type dhcpApplier struct {
	mu sync.Mutex

	pendingAddrs []string
}

func keaCredential() *syscall.Credential {
	u, err := user.Lookup(keaUser)
	if err != nil {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)} //nolint:gosec
}

func keaGroup() (int, bool) {
	u, err := user.Lookup(keaUser)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(u.Gid)
	return gid, err == nil
}

func keaOwner() []durable.Option {
	if gid, ok := keaGroup(); ok {
		return []durable.Option{durable.Owner(0, gid)}
	}
	return nil
}

func chownDirForKea(dir string) {
	gid, ok := keaGroup()
	if !ok {
		return
	}
	_ = os.Chown(dir, 0, gid) //nolint:gosec
	_ = os.Chmod(dir, 0o750)  //nolint:gosec
}

func runAsKea(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...) //nolint:gosec
	if cred := keaCredential(); cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	return cmd.CombinedOutput()
}

func newDhcpApplier() *dhcpApplier { return &dhcpApplier{} }

type dhcpParams struct {
	Plan keagen.Plan `json:"plan"`
}

func (d *dhcpApplier) dhcpApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p dhcpParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку", Data: map[string]any{"recoverable": false}}
	}

	status, err := netstatus.Collect()
	if err != nil {
		return nil, internalErr(errReadInterfaces, true)
	}
	known := map[string]bool{}
	for _, i := range status.Interfaces {
		if !i.Loopback {
			known[i.Name] = true
		}
	}
	if err := p.Plan.Validate(known); err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDHCPPlan, Message: err.Error(),
			Data: map[string]any{"recoverable": false}}
	}

	config, err := p.Plan.Generate()
	if err != nil {

		return nil, internalErr(err.Error(), false)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	keaBin, err := findBinary([]string{"/usr/sbin/kea-dhcp4", "/sbin/kea-dhcp4"})
	if err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDHCPNoTool,
			Message: "служба выдачи адресов не установлена",
			Data:    map[string]any{"recoverable": false}}
	}

	if err := durable.MkdirAll(keaConfigDir, 0o750); err != nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}
	chownDirForKea(keaConfigDir)

	staged, err := durable.Stage(keaConfigFile, config, 0o640, keaOwner()...)
	if err != nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}
	defer staged.Abort()

	waitingLink := false
	if out, err := runAsKea(keaBin, "-t", staged.Path()); err != nil {
		if strings.Contains(string(out), "not present in the system") ||
			strings.Contains(string(out), "doesn't have address") ||
			strings.Contains(string(out), "Failed to select interface") {
			waitingLink = true
		} else {
			return nil, &agentrpc.ErrorObject{Code: codeDHCPConfig,
				Message: "конфигурация выдачи адресов не прошла проверку: " + keaErrorLine(out),
				Data:    map[string]any{"recoverable": false}}
		}
	}

	changed := true
	if cur, err := os.ReadFile(keaConfigFile); err == nil && string(cur) == string(config) { //nolint:gosec
		changed = false
	}
	if changed {
		if err := staged.Commit(); err != nil {
			return nil, detailErr(errWriteConfig, err.Error(), true)
		}
	}

	dropInChanged, err := d.ensureDropIn()
	if err != nil {
		return nil, detailErr(errWriteConfig, err.Error(), true)
	}

	state, err := d.ensureService(changed, dropInChanged)
	if err != nil {
		return nil, detailErr("не удалось запустить службу выдачи адресов — попробуйте ещё раз; если повторяется, обратитесь в поддержку", err.Error(), true)
	}

	d.pendingAddrs = missingAddresses(p.Plan)
	if len(d.pendingAddrs) > 0 {
		waitingLink = true
	}
	if waitingLink && state != "active" {
		state = "waiting_link"
	}
	return map[string]any{"changed": changed || dropInChanged, "state": state}, nil
}

func (d *dhcpApplier) ensureDropIn() (bool, error) {
	if err := durable.MkdirAll(keaDropInDir, 0o755); err != nil {
		return false, err
	}
	changed, err := durable.WriteIfChanged(keaDropInFile, []byte(keaDropIn), 0o644)
	if err != nil || !changed {
		return false, err
	}
	if systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
		_ = exec.Command(systemctl, "daemon-reload").Run() //nolint:gosec
	}
	return true, nil
}

func (d *dhcpApplier) ensureService(configChanged, dropInChanged bool) (string, error) {
	systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return "unknown", err
	}
	active := exec.Command(systemctl, "is-active", "--quiet", keaServiceName).Run() == nil //nolint:gosec

	staleConfig := active && !runningWithOurConfig(systemctl)
	switch {
	case !active:
		if out, err := exec.Command(systemctl, "enable", "--now", keaServiceName).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("dhcp: enable failed: %s", firstLine(out))
			return "failed", nil
		}
	case dropInChanged || staleConfig:
		if out, err := exec.Command(systemctl, "restart", keaServiceName).CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("dhcp: restart failed: %s", firstLine(out))
		}
	case configChanged:
		if err := exec.Command(systemctl, "reload", keaServiceName).Run(); err != nil { //nolint:gosec
			log.Printf("dhcp: reload failed, restarting")
			_ = exec.Command(systemctl, "restart", keaServiceName).Run() //nolint:gosec
		}
	}
	if exec.Command(systemctl, "is-active", "--quiet", keaServiceName).Run() == nil { //nolint:gosec
		return "active", nil
	}
	return "inactive", nil
}

func missingAddresses(plan keagen.Plan) []string {
	status, err := netstatus.Collect()
	if err != nil {
		return nil
	}
	present := map[string]bool{}
	for _, i := range status.Interfaces {
		for _, a := range i.Addresses {
			present[a] = true
		}
	}
	var missing []string
	for _, l := range plan.LANs {
		if !present[l.CIDR] {
			missing = append(missing, l.CIDR)
		}
	}
	return missing
}

func (d *dhcpApplier) RestoreOnStart() {
	data, err := os.ReadFile(keaConfigFile) //nolint:gosec
	if err != nil {
		return
	}
	var cfg struct {
		Dhcp4 struct {
			Subnet4 []struct {
				Subnet     string `json:"subnet"`
				OptionData []struct {
					Name string `json:"name"`
					Data string `json:"data"`
				} `json:"option-data"`
			} `json:"subnet4"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}
	var plan keagen.Plan
	for _, sn := range cfg.Dhcp4.Subnet4 {
		prefix := ""
		if i := strings.LastIndex(sn.Subnet, "/"); i > 0 {
			prefix = sn.Subnet[i:]
		}
		for _, o := range sn.OptionData {
			if o.Name == "routers" && prefix != "" {
				plan.LANs = append(plan.LANs, keagen.LAN{CIDR: o.Data + prefix})
			}
		}
	}
	if len(plan.LANs) == 0 {
		return
	}
	d.mu.Lock()
	d.pendingAddrs = missingAddresses(plan)
	d.mu.Unlock()
	if len(d.pendingAddrs) > 0 {
		log.Printf("dhcp: waiting for link on %v", d.pendingAddrs)
	}
}

func (d *dhcpApplier) WatchLink() {
	for range time.Tick(20 * time.Second) {
		d.mu.Lock()
		pending := append([]string(nil), d.pendingAddrs...)
		d.mu.Unlock()
		if len(pending) == 0 {
			continue
		}
		status, err := netstatus.Collect()
		if err != nil {
			continue
		}
		present := map[string]bool{}
		for _, i := range status.Interfaces {
			for _, a := range i.Addresses {
				present[a] = true
			}
		}
		ready := true
		for _, addr := range pending {
			if !present[addr] {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		if systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
			log.Printf("dhcp: link is up, restarting address service")
			_ = exec.Command(systemctl, "restart", keaServiceName).Run() //nolint:gosec
		}
		d.mu.Lock()
		d.pendingAddrs = nil
		d.mu.Unlock()
	}
}

func keaErrorLine(out []byte) string {
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(l, "ERROR") || strings.Contains(l, "Fatal") || strings.Contains(l, "failed") {
			if i := strings.Index(l, "] "); i > 0 && i+2 < len(l) {
				return l[i+2:]
			}
			return l
		}
	}
	return firstLine(out)
}

func runningWithOurConfig(systemctl string) bool {
	out, err := exec.Command(systemctl, "show", keaServiceName, "-p", "MainPID", "--value").Output() //nolint:gosec
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return false
	}
	cmdline, err := os.ReadFile("/proc/" + pid + "/cmdline") //nolint:gosec
	if err != nil {
		return false
	}
	return strings.Contains(strings.ReplaceAll(string(cmdline), "\x00", " "), keaConfigFile)
}

type Lease struct {
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Expires  int64  `json:"expires"`
}

func (d *dhcpApplier) dhcpLeases(json.RawMessage) (any, *agentrpc.ErrorObject) {
	state := "missing"
	if systemctl, err := findBinary([]string{"/usr/bin/systemctl", "/bin/systemctl"}); err == nil {
		if _, ferr := findBinary([]string{"/usr/sbin/kea-dhcp4", "/sbin/kea-dhcp4"}); ferr == nil {
			state = "inactive"
			if exec.Command(systemctl, "is-active", "--quiet", keaServiceName).Run() == nil { //nolint:gosec
				state = "active"
			}
		}
	}

	leases := map[string]Lease{}
	file, err := os.Open(keagen.LeaseFile) //nolint:gosec
	if err == nil {
		defer func() { _ = file.Close() }()
		reader := csv.NewReader(file)
		reader.FieldsPerRecord = -1
		rows, rerr := reader.ReadAll()
		if rerr == nil && len(rows) > 1 {
			idx := map[string]int{}
			for i, name := range rows[0] {
				idx[strings.TrimSpace(name)] = i
			}
			now := time.Now().Unix()
			for _, row := range rows[1:] {
				get := func(name string) string {
					if i, ok := idx[name]; ok && i < len(row) {
						return row[i]
					}
					return ""
				}
				addr := get("address")
				if addr == "" {
					continue
				}
				expire, _ := strconv.ParseInt(get("expire"), 10, 64)
				leaseState := get("state")
				if expire <= now || (leaseState != "" && leaseState != "0") {
					delete(leases, addr)
					continue
				}
				leases[addr] = Lease{
					Address: addr, MAC: get("hwaddr"),
					Hostname: get("hostname"), Expires: expire,
				}
			}
		}
	}

	list := make([]Lease, 0, len(leases))
	for _, l := range leases {
		list = append(list, l)
	}
	return map[string]any{"service": state, "leases": list}, nil
}

func (d *dhcpApplier) activeLeases() []Lease {
	res, aerr := d.dhcpLeases(nil)
	if aerr != nil {
		return nil
	}
	m, ok := res.(map[string]any)
	if !ok {
		return nil
	}
	list, _ := m["leases"].([]Lease)
	return list
}
