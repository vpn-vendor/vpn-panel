package main

import (
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
)

const (
	codeQoSPlan      = 1401
	codeQoSApply     = 1402
	codeQoSNameTaken = 1403
	codeQoSNoKernel  = 1404
)

const qosStateFile = "/etc/vpn-panel/qos.json"

type qosApplier struct {
	mu sync.Mutex

	composer *modeComposer
}

func newQosApplier() *qosApplier { return &qosApplier{} }

type qosParams struct {
	Plan qosgen.Plan `json:"plan"`
}

func (q *qosApplier) RestoreOnStart() {
	plan, err := q.readState()
	if err != nil || !plan.Enabled {
		return
	}

	if plan.WAN != "" && !ifaceExists(plan.WAN) {

		log.Printf("qos: WAN queue deferred until %s comes up", plan.WAN)
		go q.applyWhenWANAppears(plan.WAN)
		return
	}

	if plan.Tunnel != "" && !ifaceExists(plan.Tunnel) {
		log.Printf("qos: tunnel queue will be applied together with the tunnel")
		plan.Tunnel = ""
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, aerr := q.applyPlan(plan); aerr != nil {
		log.Printf("qos: restore failed: %s", aerr.Message)
		return
	}
	log.Printf("qos: queue restored on %s", plan.WAN)
}

const qosWANWait = 90 * time.Second

func (q *qosApplier) applyWhenWANAppears(name string) {
	if !waitIfacePresent(name, qosWANWait) {
		log.Printf("qos: %s did not come up, queue left to the next apply", name)
		return
	}
	if _, aerr := q.qosWANUp(nil); aerr != nil {
		log.Printf("qos: queue after %s came up failed: %s", name, aerr.Message)
	}
}

func (q *qosApplier) qosWANUp(json.RawMessage) (any, *agentrpc.ErrorObject) {
	plan, err := q.readState()
	if err != nil || !plan.Enabled || plan.WAN == "" || !ifaceExists(plan.WAN) {
		return map[string]any{"applied": false}, nil
	}

	if plan.Tunnel != "" && !ifaceExists(plan.Tunnel) {
		plan.Tunnel = ""
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, aerr := q.applyPlan(plan); aerr != nil {
		return nil, aerr
	}
	log.Printf("qos: queue applied on %s after link up", plan.WAN)
	return map[string]any{"applied": true}, nil
}

func ifaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (q *qosApplier) qosCounters(json.RawMessage) (any, *agentrpc.ErrorObject) {
	plan, err := q.readState()
	if err != nil {
		return map[string]any{"drops": map[string]int64{}}, nil
	}
	tc, terr := findBinary(tcCandidates)
	if terr != nil {
		return nil, internalErr(errToolMissing, false)
	}
	drops := map[string]int64{}
	for _, dev := range []string{plan.WAN, qosgen.IFBDevice, plan.Tunnel, qosgen.IFBTunnelDevice} {
		if dev == "" || !ifaceExists(dev) {
			continue
		}
		out, cerr := exec.Command(tc, "-s", "qdisc", "show", "dev", dev).Output() //nolint:gosec
		if cerr != nil {
			continue
		}
		drops[dev] = qosgen.ParseDropped(out)
	}
	return map[string]any{"drops": drops}, nil
}

func (q *qosApplier) qosApply(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p qosParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку", Data: map[string]any{"recoverable": false}}
	}

	facts := p.Plan
	if q.composer != nil {
		p.Plan = q.composer.QoSWith(facts)
	}
	if p.Plan.Enabled {
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
			return nil, &agentrpc.ErrorObject{Code: codeQoSPlan, Message: err.Error(),
				Data: map[string]any{"recoverable": false}}
		}
	}

	changed, aerr := q.applyAndPersist(p.Plan)
	if aerr != nil {
		return nil, aerr
	}
	if q.composer != nil {
		q.composer.SetQoSFacts(facts)
	}
	return map[string]any{
		"changed":   changed,
		"down_kbit": p.Plan.ShapedDownKbit(),
		"up_kbit":   p.Plan.ShapedUpKbit(),
	}, nil
}

func (q *qosApplier) applyAndPersist(plan qosgen.Plan) (bool, *agentrpc.ErrorObject) {
	q.mu.Lock()
	defer q.mu.Unlock()

	prev, _ := q.readState()
	if prev.Tunnel != "" && prev.Tunnel != plan.Tunnel {
		q.teardownTunnel(prev.Tunnel)
	}

	var changed bool
	var aerr *agentrpc.ErrorObject
	if plan.Enabled {
		changed, aerr = q.applyPlan(plan)
	} else {
		changed, aerr = q.teardown()
	}
	if aerr != nil {
		return false, aerr
	}
	if err := q.writeState(plan); err != nil {
		return false, detailErr(errWriteConfig, err.Error(), true)
	}
	return changed, nil
}

func (q *qosApplier) qosStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	plan, _ := q.readState()

	active := false
	if plan.WAN != "" {
		if tc, err := findBinary(tcCandidates); err == nil {
			if out, err := exec.Command(tc, "-j", "qdisc", "show", "dev", plan.WAN).Output(); err == nil { //nolint:gosec
				if bw, found, _ := qosgen.ActiveCake(out); found &&
					bw == qosgen.CakeBandwidthBytes(plan.ShapedUpKbit()) {
					active = true
				}
			}
		}
	}

	linkMbit := -1
	if plan.WAN != "" {

		if data, err := os.ReadFile("/sys/class/net/" + plan.WAN + "/speed"); err == nil {
			linkMbit = qosgen.ParseLinkSpeedMbit(string(data))
		}
	}
	load1 := ""
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		load1 = qosgen.ParseLoad1(string(data))
	}

	return map[string]any{
		"enabled":   plan.Enabled,
		"active":    active,
		"wan":       plan.WAN,
		"down_kbit": plan.DownKbit,
		"up_kbit":   plan.UpKbit,
		"cores":     runtime.NumCPU(),
		"load1":     load1,
		"link_mbit": linkMbit,
	}, nil
}

var (
	tcCandidates       = []string{"/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc"}
	ipCandidates       = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"}
	modprobeCandidates = []string{"/usr/sbin/modprobe", "/sbin/modprobe"}
)

func (q *qosApplier) applyPlan(plan qosgen.Plan) (bool, *agentrpc.ErrorObject) {
	tc, err := findBinary(tcCandidates)
	if err != nil {
		return false, &agentrpc.ErrorObject{Code: codeQoSApply,
			Message: "утилита управления очередями не найдена",
			Data:    map[string]any{"recoverable": false}}
	}
	ip, err := findBinary(ipCandidates)
	if err != nil {
		return false, internalErr(errToolMissing, false)
	}

	if modprobe, err := findBinary(modprobeCandidates); err == nil {
		for _, mod := range []string{"sch_cake", "ifb"} {
			if out, merr := exec.Command(modprobe, mod).CombinedOutput(); merr != nil { //nolint:gosec
				return false, &agentrpc.ErrorObject{Code: codeQoSNoKernel,
					Message: "ядро системы не поддерживает умную очередь: " + firstLine(out),
					Data:    map[string]any{"recoverable": false}}
			}
		}
	}

	if q.currentMatches(tc, plan) {
		return false, nil
	}

	if aerr := ensureIFB(ip, qosgen.IFBDevice); aerr != nil {
		return false, aerr
	}
	if plan.Tunnel != "" {
		if aerr := ensureIFB(ip, qosgen.IFBTunnelDevice); aerr != nil {
			return false, aerr
		}
	}
	for _, args := range plan.Commands() {
		if out, cerr := exec.Command(tc, args...).CombinedOutput(); cerr != nil { //nolint:gosec
			return false, &agentrpc.ErrorObject{Code: codeQoSApply,
				Message: "не удалось применить очередь: " + firstLine(out),
				Data:    map[string]any{"recoverable": true}}
		}
	}
	if !q.currentMatches(tc, plan) {
		return false, &agentrpc.ErrorObject{Code: codeQoSApply,
			Message: "очередь применена, но проверка состояния не подтвердила её",
			Data:    map[string]any{"recoverable": true}}
	}
	return true, nil
}

func (q *qosApplier) currentMatches(tc string, plan qosgen.Plan) bool {
	if !pairMatches(tc, plan.WAN, qosgen.IFBDevice,
		plan.ShapedUpKbit(), plan.ShapedDownKbit()) {
		return false
	}
	if plan.Tunnel == "" {
		return true
	}
	return pairMatches(tc, plan.Tunnel, qosgen.IFBTunnelDevice,
		plan.TunnelUpKbit(), plan.TunnelDownKbit())
}

func pairMatches(tc, dev, ifb string, upKbit, downKbit int) bool {
	devOut, err := exec.Command(tc, "-j", "qdisc", "show", "dev", dev).Output() //nolint:gosec
	if err != nil {
		return false
	}
	bw, found, jerr := qosgen.ActiveCake(devOut)
	if jerr != nil || !found || bw != qosgen.CakeBandwidthBytes(upKbit) {
		return false
	}
	if !qosgen.HasIngress(devOut) {
		return false
	}
	ifbOut, err := exec.Command(tc, "-j", "qdisc", "show", "dev", ifb).Output() //nolint:gosec
	if err != nil {
		return false
	}
	bw, found, jerr = qosgen.ActiveCake(ifbOut)
	return jerr == nil && found && bw == qosgen.CakeBandwidthBytes(downKbit)
}

func ensureIFB(ip, dev string) *agentrpc.ErrorObject {
	out, err := exec.Command(ip, "-j", "-d", "link", "show", "dev", dev).Output() //nolint:gosec
	if err == nil {
		var links []struct {
			LinkInfo struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if json.Unmarshal(out, &links) != nil || len(links) == 0 ||
			links[0].LinkInfo.Kind != "ifb" {
			return &agentrpc.ErrorObject{Code: codeQoSNameTaken,
				Message: "имя служебного устройства очереди занято другим программным обеспечением",
				Data:    map[string]any{"recoverable": false}}
		}
	} else {
		if out, cerr := exec.Command(ip, "link", "add", dev, "type", "ifb").CombinedOutput(); cerr != nil { //nolint:gosec
			return detailErr("не удалось создать служебное устройство очереди — обратитесь в поддержку", string(out), true)
		}
	}
	if out, cerr := exec.Command(ip, "link", "set", dev, "up").CombinedOutput(); cerr != nil { //nolint:gosec
		return detailErr("не удалось включить служебное устройство очереди — обратитесь в поддержку", string(out), true)
	}
	return nil
}

func (q *qosApplier) teardownTunnel(dev string) {
	if tc, err := findBinary(tcCandidates); err == nil {
		_ = exec.Command(tc, "qdisc", "del", "dev", dev, "root").Run()    //nolint:gosec
		_ = exec.Command(tc, "qdisc", "del", "dev", dev, "ingress").Run() //nolint:gosec
	}
	if ip, err := findBinary(ipCandidates); err == nil {
		if exec.Command(ip, "link", "show", "dev", qosgen.IFBTunnelDevice).Run() == nil { //nolint:gosec
			_ = exec.Command(ip, "link", "del", qosgen.IFBTunnelDevice).Run() //nolint:gosec
		}
	}
}

func (q *qosApplier) teardown() (bool, *agentrpc.ErrorObject) {
	prev, err := q.readState()
	if err != nil || prev.WAN == "" {
		return false, nil
	}
	tc, err := findBinary(tcCandidates)
	if err != nil {
		return false, nil
	}
	changed := false
	wanOut, err := exec.Command(tc, "-j", "qdisc", "show", "dev", prev.WAN).Output() //nolint:gosec
	if err == nil {
		if _, found, _ := qosgen.ActiveCake(wanOut); found {
			_ = exec.Command(tc, "qdisc", "del", "dev", prev.WAN, "root").Run() //nolint:gosec
			changed = true
		}
		if qosgen.HasIngress(wanOut) {
			_ = exec.Command(tc, "qdisc", "del", "dev", prev.WAN, "ingress").Run() //nolint:gosec
			changed = true
		}
	}
	if prev.Tunnel != "" {
		q.teardownTunnel(prev.Tunnel)
		changed = true
	}
	if ip, err := findBinary(ipCandidates); err == nil {
		if exec.Command(ip, "link", "show", "dev", qosgen.IFBDevice).Run() == nil { //nolint:gosec
			_ = exec.Command(ip, "link", "del", qosgen.IFBDevice).Run() //nolint:gosec
			changed = true
		}
	}
	return changed, nil
}

func (q *qosApplier) readState() (qosgen.Plan, error) {
	var plan qosgen.Plan
	data, err := os.ReadFile(qosStateFile)
	if err != nil {
		return plan, err
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return qosgen.Plan{}, err
	}
	return plan, nil
}

func (q *qosApplier) writeState(plan qosgen.Plan) error {
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}

	return durable.Write(qosStateFile, append(data, '\n'), 0o600)
}
