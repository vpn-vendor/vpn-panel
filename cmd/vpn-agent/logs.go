package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	codeLogsParams = 1901
	codeLogsBusy   = 1902
	codeLogsIO     = 1903

	logDir = "/var/log"

	keepTail = 4 << 20
)

var syslogFiles = map[string]bool{
	"syslog": true, "kern.log": true, "auth.log": true, "user.log": true, "mail.log": true, "cron.log": true,
}

type logsApplier struct {
	mu      sync.Mutex
	limiter *ratelimit.Limiter
}

func newLogsApplier() *logsApplier { return &logsApplier{limiter: ratelimit.New(6, 1, 10*time.Second)} }

type logsTrimParams struct {
	Files []string `json:"files"`
}

type logsTrimResult struct {
	Freed uint64            `json:"freed"`
	Files map[string]uint64 `json:"files"`
}

func (l *logsApplier) logsTrim(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p logsTrimParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &agentrpc.ErrorObject{Code: codeLogsParams, Message: "запрос составлен неверно"}
		}
	}
	names := p.Files
	if len(names) == 0 {
		for n := range syslogFiles {
			names = append(names, n)
		}
	}

	for _, n := range names {
		if !syslogFiles[n] {
			return nil, &agentrpc.ErrorObject{Code: codeLogsParams, Message: "такой журнал панель не обслуживает"}
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.limiter.Allow("trim") {
		return nil, agentrpc.Busy(codeLogsBusy, "журналы только что обрезались — подождите минуту", l.limiter.RetryIn("trim"))
	}
	res := logsTrimResult{Files: map[string]uint64{}}
	var firstErr error
	for _, n := range names {
		freed, err := trimLog(n)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		res.Files[n] = freed
		res.Freed += freed
	}

	_ = exec.Command("systemctl", "kill", "-s", "HUP", "--kill-whom=main", "rsyslog.service").Run() //nolint:gosec
	if firstErr != nil {
		return nil, &agentrpc.ErrorObject{Code: codeLogsIO, Message: "часть журналов обрезать не удалось",
			Data: map[string]any{"detail": firstErr.Error()}}
	}
	return res, nil
}

func trimLog(name string) (uint64, error) {
	var freed uint64
	live := filepath.Join(logDir, name)
	if st, err := os.Stat(live); err == nil && st.Size() > keepTail {
		before := uint64(st.Size()) //nolint:gosec
		if err := keepTailOf(live, st.Size()); err != nil {
			return freed, err
		}
		freed += before - keepTail
	}
	matches, _ := filepath.Glob(live + ".*")
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || st.IsDir() {
			continue
		}
		if err := os.Remove(m); err != nil { //nolint:gosec
			return freed, err
		}
		freed += uint64(st.Size()) //nolint:gosec
	}
	return freed, nil
}

func keepTailOf(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tail := make([]byte, keepTail)
	n, err := f.ReadAt(tail, size-keepTail)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	tail = tail[:n]
	for i, b := range tail {
		if b == '\n' {
			tail = tail[i+1:]
			break
		}
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.WriteAt(tail, 0)
	return err
}
