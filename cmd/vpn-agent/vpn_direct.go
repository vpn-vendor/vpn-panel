package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/speedtest"
)

const (
	directSeconds  = 8
	directStreams  = 4
	directMaxBytes = 400 << 20
)

func (v *vpnApplier) vpnSpeedDirect(json.RawMessage) (any, *agentrpc.ErrorObject) {

	src := speedtest.DownSources[0]

	mark := currentTunnelFwmark()
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: markSocket(mark),
	}
	client := &http.Client{
		Timeout: time.Duration(directSeconds+10) * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), directSeconds*time.Second)
	defer cancel()

	var total int64
	done := make(chan int64, directStreams)
	start := time.Now()
	for i := 0; i < directStreams; i++ {
		go func() {
			var n int64
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
			if err != nil {
				done <- 0
				return
			}

			req.Header.Set("User-Agent", "curl/8")
			resp, err := client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				done <- 0
				return
			}
			n, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, directMaxBytes/directStreams))
			done <- n
		}()
	}
	for i := 0; i < directStreams; i++ {
		total += <-done
	}
	took := time.Since(start)

	if total == 0 {
		return nil, &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "источник замера не ответил — повторите позже",
			Data:    map[string]any{"recoverable": true}}
	}
	kbit := int(float64(total) * 8 / took.Seconds() / 1000)
	return map[string]any{
		"down_kbit": kbit,
		"source":    src.Name,
		"seconds":   int(took.Seconds()),
		"marked":    mark > 0,
	}, nil
}
