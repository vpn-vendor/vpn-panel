package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
)

const manualRetryGap = time.Minute

var manualRetry struct {
	mu sync.Mutex
	at bootInstant
}

func manualWait(at, now bootInstant) time.Duration {
	if at.IsZero() {
		return 0
	}
	if left := at.Add(manualRetryGap).Sub(now); left > 0 {
		return left
	}
	return 0
}

func reconnectRefusal(mode, slug string, wait time.Duration) *agentrpc.ErrorObject {
	if mode != modeBlack || slug == "" {
		return &agentrpc.ErrorObject{Code: codeVPNParams,
			Message: "VPN выключен — переподключать нечего",
			Data:    map[string]any{"recoverable": false}}
	}
	if wait > 0 {
		sec := int64((wait + time.Second - 1) / time.Second)
		return &agentrpc.ErrorObject{Code: codeVPNBusy,
			Message: fmt.Sprintf("переподключать вручную можно не чаще раза в минуту — подождите %d с", sec),
			Data:    map[string]any{"recoverable": true, "retry_in_sec": sec}}
	}
	return nil
}

func manualRetryWait() time.Duration {
	manualRetry.mu.Lock()
	defer manualRetry.mu.Unlock()
	now, ok := bootNow()
	if !ok {
		return 0
	}
	return manualWait(manualRetry.at, now)
}

func (v *vpnApplier) vpnReconnect(json.RawMessage) (any, *agentrpc.ErrorObject) {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.readState()
	if e := reconnectRefusal(st.Plan.Mode, st.Plan.Slug, manualRetryWait()); e != nil {
		return nil, e
	}
	if now, ok := bootNow(); ok {
		manualRetry.mu.Lock()
		manualRetry.at = now
		manualRetry.mu.Unlock()
	}
	v.clearPause(&st)
	v.resetBackoff()
	v.kickWatchdog()
	log.Printf("vpn: administrator asked to reconnect now")
	return map[string]any{"started": true, "retry_gap_sec": int64(manualRetryGap / time.Second)}, nil
}
