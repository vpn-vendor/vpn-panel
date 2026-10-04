package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/sntp"
)

const (
	codeTimeParams = 1701
	codeTimeBusy   = 1702
	codeTimeNoAns  = 1703
	codeTimeSet    = 1704
)

const (
	timeQueryTimeout = 3 * time.Second
	timeTotalTimeout = 12 * time.Second
)

type timeApplier struct {
	mu      sync.Mutex
	limiter *ratelimit.Limiter
}

func newTimeApplier() *timeApplier {

	return &timeApplier{limiter: ratelimit.New(3, 1, time.Minute)}
}

var (
	hwclockCandidates     = []string{"/usr/sbin/hwclock", "/sbin/hwclock"}
	timedatectlCandidates = []string{"/usr/bin/timedatectl", "/bin/timedatectl"}
)

func (t *timeApplier) timeSync(json.RawMessage) (any, *agentrpc.ErrorObject) {
	if !t.limiter.Allow("timesync") {
		return nil, agentrpc.Busy(codeTimeBusy, "проверка времени запускалась только что — подождите минуту", t.limiter.RetryIn("timesync"))
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	mark := currentTunnelFwmark()

	offset, server, err := queryTime(mark)
	if err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeTimeNoAns,
			Message: "не удалось спросить точное время: сервер не видит интернет. Проверьте кабель провайдера и попробуйте ещё раз",
			Data:    map[string]any{"recoverable": true, "detail": err.Error()}}
	}

	res := map[string]any{
		"offset_sec": int64(offset / time.Second),
		"server":     server,
		"changed":    false,
	}
	if offset < sntp.Negligible && offset > -sntp.Negligible {
		log.Printf("timesync: clock is accurate (offset %s)", offset.Round(time.Millisecond))
		return res, nil
	}

	if aerr := setClock(offset); aerr != nil {
		return nil, aerr
	}
	res["changed"] = true
	log.Printf("timesync: clock corrected by %s from %s", offset.Round(time.Second), server)
	return res, nil
}

func queryTime(mark int) (time.Duration, string, error) {
	deadline := time.Now().Add(timeTotalTimeout)
	var lastErr error
	for _, server := range sntp.Servers {
		if time.Now().After(deadline) {
			break
		}
		offset, err := askServer(server, mark)
		if err != nil {
			lastErr = err
			continue
		}
		return offset, server, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("нет ответа")
	}
	return 0, "", lastErr
}

func askServer(server string, mark int) (time.Duration, error) {
	d := net.Dialer{Timeout: timeQueryTimeout, Control: markSocket(mark)}
	conn, err := d.Dial("udp", net.JoinHostPort(server, "123"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeQueryTimeout)); err != nil {
		return 0, err
	}

	t1 := time.Now()
	if _, err := conn.Write(sntp.Request()); err != nil {
		return 0, err
	}
	buf := make([]byte, sntp.PacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	t4 := time.Now()
	return sntp.Offset(buf[:n], t1, t4)
}

func clockTarget(now time.Time, offset time.Duration) string {
	return now.Add(offset).Format("2006-01-02 15:04:05")
}

func setClock(offset time.Duration) *agentrpc.ErrorObject {
	timedatectl, err := findBinary(timedatectlCandidates)
	if err != nil {
		return internalErr(errToolMissing, false)
	}

	_ = exec.Command(timedatectl, "set-ntp", "false").Run() //nolint:gosec

	target := clockTarget(time.Now(), offset)

	if out, cerr := exec.Command(timedatectl, "set-time", target).CombinedOutput(); cerr != nil { //nolint:gosec
		_ = exec.Command(timedatectl, "set-ntp", "true").Run() //nolint:gosec
		return detailErr("не удалось перевести часы сервера — обратитесь в поддержку", firstLine(out), false)
	}

	if hwclock, herr := findBinary(hwclockCandidates); herr == nil {
		if out, cerr := exec.Command(hwclock, "--systohc").CombinedOutput(); cerr != nil { //nolint:gosec
			log.Printf("timesync: could not persist time to hardware clock: %s", firstLine(out))
		}
	}

	_ = exec.Command(timedatectl, "set-ntp", "true").Run() //nolint:gosec
	return nil
}
