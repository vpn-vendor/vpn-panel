package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"github.com/vpn-vendor/vpn-panel-core/internal/policy"
)

const policyKeyring = "/usr/share/keyrings/vpn-panel.asc"

var policyStatePath = "/etc/vpn-panel/policy.json"

var (
	policyMinInterval = time.Minute
	policyMaxInterval = 24 * time.Hour

	policyHTTPTimeout = 30 * time.Second
)

type policyReader interface {
	Flag(name string) bool
}

type policyApplier struct {
	mu      sync.Mutex
	current policy.Policy
	base    string
	stop    chan struct{}

	reconcilers []func()

	download func(url string) ([]byte, error)
	verify   func(doc, sig []byte) error
}

func (pa *policyApplier) Flag(name string) bool { return pa.get().Bool(name) }

func (pa *policyApplier) OnChange(fn func()) { pa.reconcilers = append(pa.reconcilers, fn) }

func (pa *policyApplier) reconcile() {
	for _, fn := range pa.reconcilers {
		fn()
	}
}

func newPolicyApplier() *policyApplier {
	base := os.Getenv("VPN_PANEL_REPO")
	if base == "" {
		base = "https://vpn-vendor.github.io/vpn-panel"
	}
	pa := &policyApplier{current: policy.Default(), base: strings.TrimRight(base, "/"), stop: make(chan struct{})}
	pa.download = httpGet
	pa.verify = gpgvVerify

	if data, err := os.ReadFile(policyStatePath); err == nil { //nolint:gosec
		if p, _, perr := policy.Parse(data); perr == nil {
			pa.current = p
		}
	}
	return pa
}

func (pa *policyApplier) get() policy.Policy {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	return pa.current
}

type policyFlagDTO struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
	Why  string `json:"why"`
}

type policyStatusDTO struct {
	Flags    []policyFlagDTO `json:"flags"`
	Advisory policy.Advisory `json:"advisory"`
	KnownBad []string        `json:"known_bad"`
}

func (pa *policyApplier) policyStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	p := pa.get()
	flags := make([]policyFlagDTO, 0, len(policy.Registry()))
	for _, f := range policy.Registry() {
		flags = append(flags, policyFlagDTO{Name: f.Name, On: p.Bool(f.Name), Why: f.Why})
	}
	return policyStatusDTO{Flags: flags, Advisory: p.Advisory(), KnownBad: p.KnownBad()}, nil
}

func (pa *policyApplier) fetchOnce() (changed bool, err error) {
	doc, err := pa.download(pa.base + "/policy.json")
	if err != nil {
		return false, fmt.Errorf("документ политики не скачан: %w", err)
	}
	sig, err := pa.download(pa.base + "/policy.json.asc")
	if err != nil {
		return false, fmt.Errorf("подпись политики не скачана: %w", err)
	}
	if err := pa.verify(doc, sig); err != nil {
		return false, fmt.Errorf("подпись политики не подтверждена: %w", err)
	}
	p, warn, err := policy.Parse(doc)
	if err != nil {
		return false, fmt.Errorf("документ политики негоден: %w", err)
	}
	for _, w := range warn {
		log.Printf("policy: %s", w)
	}
	wrote, werr := durable.WriteIfChanged(policyStatePath, doc, 0o644)
	if werr != nil {
		return false, fmt.Errorf("политику не записать: %w", werr)
	}
	pa.mu.Lock()
	pa.current = p
	pa.mu.Unlock()
	return wrote, nil
}

func (pa *policyApplier) run() {
	interval := policyMinInterval
	for {
		changed, err := pa.fetchOnce()
		switch {
		case err != nil:
			log.Printf("policy: %v (держим последнюю хорошую)", err)
			interval = backoff(interval)
		case changed || pa.get().Advisory().PullNow:
			interval = policyMinInterval
		default:
			interval = backoff(interval)
		}

		if err == nil {
			pa.reconcile()
		}
		select {
		case <-pa.stop:
			return
		case <-time.After(interval):
		}
	}
}

func backoff(d time.Duration) time.Duration {
	d *= 2
	if d > policyMaxInterval {
		d = policyMaxInterval
	}
	return d
}

func (pa *policyApplier) StopPolling() { close(pa.stop) }

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: policyHTTPTimeout}
	resp, err := client.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ответ %s", resp.Status)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 256<<10))
}

func gpgvVerify(doc, sig []byte) error {
	dir, err := os.MkdirTemp("", "vpn-policy-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	docPath := filepath.Join(dir, "policy.json")
	sigPath := filepath.Join(dir, "policy.json.asc")
	krPath := filepath.Join(dir, "keyring.gpg")
	if err := os.WriteFile(docPath, doc, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return err
	}
	if out, derr := exec.Command("gpg", "--batch", "--yes", "-o", krPath, "--dearmor", policyKeyring).CombinedOutput(); derr != nil { //nolint:gosec
		return fmt.Errorf("ключ не дезармирован: %s", strings.TrimSpace(string(out)))
	}
	out, verr := exec.Command("gpgv", "--keyring", krPath, sigPath, docPath).CombinedOutput() //nolint:gosec
	if verr != nil {
		return fmt.Errorf("gpgv отверг подпись: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
