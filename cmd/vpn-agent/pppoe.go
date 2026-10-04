package main

import (
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
)

const (
	pppoePeerName = "vpn_panel_wan"
	pppoePeerPath = "/etc/ppp/peers/" + pppoePeerName
	pppoeUnit     = "ppp@" + pppoePeerName + ".service"
)

const (
	pppoeChapSecret = "/etc/ppp/chap-secrets" //nolint:gosec
	pppoePapSecret  = "/etc/ppp/pap-secrets"  //nolint:gosec
)

const pppoeBackupSuffix = ".vpn-panel.prev"

var pppoeManagedFiles = []struct {
	path string
	mode os.FileMode
}{
	{pppoePeerPath, 0o644},
	{pppoeChapSecret, 0o600},
	{pppoePapSecret, 0o600},
}

func backupPPPoEFiles() {
	for _, f := range pppoeManagedFiles {
		data, err := os.ReadFile(f.path) //nolint:gosec
		if err != nil {
			data = []byte(backupAbsentMarker)
		}
		if err := durable.Write(f.path+pppoeBackupSuffix, data, 0o600); err != nil {
			log.Printf("pppoe: backup of %s not saved: %v", f.path, err)
		}
	}
}

func restorePPPoEFiles() {
	for _, f := range pppoeManagedFiles {
		data, err := os.ReadFile(f.path + pppoeBackupSuffix) //nolint:gosec
		if err != nil {
			continue
		}
		if string(data) == backupAbsentMarker {
			err = durable.Remove(f.path)
		} else {
			err = durable.Write(f.path, data, f.mode)
		}
		if err != nil {

			log.Printf("pppoe: %s not restored: %v", f.path, err)
			continue
		}
		_ = durable.Remove(f.path + pppoeBackupSuffix)
	}
}

func clearPPPoEBackups() {
	for _, f := range pppoeManagedFiles {
		_ = durable.Remove(f.path + pppoeBackupSuffix)
	}
}

func pppoeBackupsLeft() bool {
	for _, f := range pppoeManagedFiles {
		if _, err := os.Stat(f.path + pppoeBackupSuffix); err == nil {
			return true
		}
	}
	return false
}

func validPPPoEUser(u string) bool { return netplangen.ValidPPPoEUsername(u) }

func validPPPoESecret(p string) bool {
	return p != "" && !strings.ContainsAny(p, "\"\n\r")
}

func pppoePeerContent(nic, username string) string {

	return "plugin pppoe.so nic-" + nic + "\n" +
		"user \"" + username + "\"\n" +
		"noauth\n" +
		"hide-password\n" +
		"defaultroute\n" +
		"replacedefaultroute\n" +
		"noipdefault\n" +
		"persist\n" +

		"maxfail 1\n" +
		"holdoff 10\n" +
		"lcp-echo-interval 30\n" +
		"lcp-echo-failure 4\n" +

		"ipparam " + pppoePeerName + "\n" +
		"mtu 1492\n" +
		"mru 1492\n"
}

func writePPPoEPeer(nic, username string) (bool, error) {
	if !validPPPoEUser(username) {
		return false, fmt.Errorf("логин PPPoE содержит недопустимые символы")
	}
	peer := pppoePeerContent(nic, username)
	if err := durable.MkdirAll(filepath.Dir(pppoePeerPath), 0o755); err != nil {
		return false, err
	}

	return durable.WriteIfChanged(pppoePeerPath, []byte(peer), 0o644)
}

func setPPPoESecret(username, password string) error {
	if password == "" {
		return nil
	}
	if !validPPPoEUser(username) || !validPPPoESecret(password) {
		return fmt.Errorf("логин или пароль PPPoE содержит недопустимые символы")
	}
	line := "\"" + username + "\" * \"" + password + "\" *"
	for _, path := range []string{pppoeChapSecret, pppoePapSecret} {
		if err := replaceSecretLine(path, username, line); err != nil {
			return err
		}
	}
	return nil
}

func replaceSecretLine(path, username, line string) error {
	var kept []string
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec
		for _, ln := range strings.Split(string(data), "\n") {
			if ln == "" {
				continue
			}

			first := strings.TrimSpace(ln)
			if i := strings.IndexAny(first, " \t"); i >= 0 {
				first = first[:i]
			}
			if strings.Trim(first, "\"") == username {
				continue
			}
			kept = append(kept, ln)
		}
	}
	kept = append(kept, line)
	return durable.Write(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

func pppoeStart() error {
	if err := runSystemctl(false, "enable", pppoeUnit); err != nil {
		return err
	}

	return runSystemctl(true, "restart", pppoeUnit)
}

func pppoeStop() {
	_ = runSystemctl(false, "disable", pppoeUnit)
	_ = runSystemctl(true, "stop", pppoeUnit)
}

func pppoeUp() bool {
	return ifacePresent(netplangen.IfacePPPoE) && ifaceIPv4(netplangen.IfacePPPoE) != ""
}

func pppoeUnitActive() bool { return pppoeUnitState("is-active") == "active" }

func pppoeUnitEnabled() bool { return pppoeUnitState("is-enabled") == "enabled" }

func pppoeUnitState(query string, extra ...string) string {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return ""
	}
	args := append([]string{query}, extra...)
	args = append(args, pppoeUnit)
	out, _ := exec.Command(bin, args...).Output() //nolint:gosec
	return strings.TrimSpace(string(out))
}

const (
	pppdAuthUsRejected   = 19
	pppdAuthPeerRejected = 11
	pppdNegotiationFail  = 10
	pppdConnectFail      = 8
	pppdEchoTimeout      = 15
)

func pppoeFailureText(code int) (string, bool) {
	switch code {
	case pppdAuthUsRejected:
		return "Провайдер не принял логин или пароль. Проверьте их в договоре и примените снова — панель продолжает попытки сама, но с большими паузами.", true
	case pppdAuthPeerRejected:
		return "Провайдер не подтвердил себя при подключении. Обратитесь к нему: со стороны офиса это не чинится.", true
	case pppdNegotiationFail:
		return "Подключение к провайдеру не сошлось по настройкам. Уточните у него параметры подключения и примените снова.", true
	case pppdEchoTimeout:
		return "Провайдер перестал отвечать, и подключение было разорвано. Панель поднимает его сама.", false
	case pppdConnectFail:
		return "Провайдер не отозвался на запрос подключения. Проверьте кабель и номер тега, если он у вас есть.", false
	}
	return "", false
}

func pppoeExitStatus() int {
	out := pppoeUnitState("show", "-p", "ExecMainStatus", "--value")
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0
	}
	return n
}

func pppoeWaitOutcome(timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pppoeUp() {
			return true, ""
		}
		if text, final := pppoeFailureText(pppoeExitStatus()); final {
			return false, text
		}
		time.Sleep(500 * time.Millisecond)
	}

	if text, _ := pppoeFailureText(pppoeExitStatus()); text != "" {
		return false, text
	}
	return false, ""
}

func runSystemctl(noBlock bool, action, unit string) error {
	bin, err := findBinary(ovpnSystemctl)
	if err != nil {
		return err
	}
	args := []string{action}
	if noBlock {
		args = append(args, "--no-block")
	}
	args = append(args, unit)
	out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec
	if err != nil && action != "disable" && action != "stop" {
		return fmt.Errorf("systemctl %s %s: %s", action, unit, strings.TrimSpace(string(out)))
	}
	return nil
}

const pppoeUpWait = 40 * time.Second

const vlanUpWait = 15 * time.Second

func waitIfacePresent(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if ifacePresent(name) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (a *netplanApplier) bringUpEffectiveWAN(p applyParams) *agentrpc.ErrorObject {

	for _, in := range p.Plan.Interfaces {
		if in.Role != netplangen.RoleWAN {
			continue
		}
		link := netplangen.LinkIface(in.Name, in.VLAN)
		if link == in.Name {
			continue
		}
		if !waitIfacePresent(link, vlanUpWait) {
			return &agentrpc.ErrorObject{Code: codeVPNUp,
				Message: "Подключение с тегом VLAN не поднялось. Проверьте номер тега у провайдера и примените снова.",
				Data:    map[string]any{"recoverable": true}}
		}
	}

	var wan *netplangen.PlanInterface
	for i := range p.Plan.Interfaces {
		in := &p.Plan.Interfaces[i]
		if in.Role == netplangen.RoleWAN && in.Method == netplangen.MethodPPPoE {
			wan = in
			break
		}
	}
	if wan == nil {

		a.pppoePrevEnabled, a.pppoeTouched = pppoeUnitEnabled(), true
		pppoeStop()
		return nil
	}

	a.pppoePrevEnabled, a.pppoeTouched = pppoeUnitEnabled(), true
	backupPPPoEFiles()

	peerChanged, err := writePPPoEPeer(netplangen.LinkIface(wan.Name, wan.VLAN), wan.Username)
	if err != nil {
		return detailErr("не удалось настроить PPPoE-подключение — проверьте логин и обратитесь в поддержку", err.Error(), false)
	}
	if err := setPPPoESecret(wan.Username, p.PPPoEPassword); err != nil {
		return detailErr("не удалось сохранить данные PPPoE", err.Error(), false)
	}

	if !peerChanged && p.PPPoEPassword == "" && pppoeUp() && pppoeUnitActive() {
		log.Printf("pppoe: link already up and unchanged, not touching it")
		return nil
	}

	if err := pppoeStart(); err != nil {
		return detailErr("не удалось запустить PPPoE-подключение — попробуйте ещё раз", err.Error(), true)
	}
	if ok, named := pppoeWaitOutcome(pppoeUpWait); !ok {

		msg := named
		if msg == "" {
			msg = "Подключение к провайдеру не поднялось за отведённое время. Проверьте кабель, логин и пароль и примените снова."
		}
		return &agentrpc.ErrorObject{Code: codeVPNUp,
			Message: msg,
			Data:    map[string]any{"recoverable": true}}
	}
	return nil
}

func (a *netplanApplier) tearDownEffectiveWAN() {
	if !a.pppoeTouched {
		return
	}
	a.pppoeTouched = false
	restorePPPoEFiles()
	if a.pppoePrevEnabled {

		if err := pppoeStart(); err != nil {
			log.Printf("pppoe: previous link not restored: %v", err)
		}
		return
	}
	pppoeStop()
}
