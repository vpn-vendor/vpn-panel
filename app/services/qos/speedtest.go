package qos

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"time"

	"sync"

	"github.com/vpn-vendor/vpn-panel-core/internal/speedtest"
)

const (
	SettingMeasuredDown = "qos.measured_down_kbit"
	SettingMeasuredUp   = "qos.measured_up_kbit"
	SettingMeasuredAt   = "qos.measured_at"

	SettingMeasuredVia = "qos.measured_via"

	ViaDirect = "direct"
	ViaTunnel = "tunnel"

	SettingDirectDown = "qos.direct_down_kbit"
	SettingDirectAt   = "qos.direct_at"
)

var (
	stMu      sync.Mutex
	stRunning bool
	stResult  *speedtest.Result
	stError   string
)

type SpeedtestState struct {
	Running bool
	Result  *speedtest.Result
	Error   string
}

func (s *Service) StartSpeedtest() error {
	stMu.Lock()
	defer stMu.Unlock()
	if stRunning {
		return errors.New("замер уже идёт — дождитесь результата")
	}
	stRunning = true
	stResult = nil
	stError = ""
	go s.runSpeedtest()
	return nil
}

func (s *Service) runSpeedtest() {
	plan := s.BuildPlan()
	paused := false
	if plan.Enabled && plan.WAN != "" {
		off := plan
		off.Enabled = false
		if _, err := s.Apply(off); err == nil {
			paused = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	res, err := speedtest.New().Measure(ctx)
	cancel()

	if paused {
		if _, aerr := s.Apply(plan); aerr != nil {
			log.Printf("qos: очередь не вернулась после замера: %v", aerr)
		}
	}

	stMu.Lock()
	defer stMu.Unlock()
	stRunning = false
	if err != nil {
		stError = err.Error()
		return
	}
	stResult = res
	via := s.currentPath()
	s.setSetting(SettingMeasuredVia, via)
	if via == ViaDirect {
		s.SaveDirectBaseline(res.DownKbit, res.MeasuredAt)
	}
	s.setSetting(SettingMeasuredDown, strconv.Itoa(res.DownKbit))
	s.setSetting(SettingMeasuredUp, strconv.Itoa(res.UpKbit))
	s.setSetting(SettingMeasuredAt, res.MeasuredAt.Format(time.RFC3339))
}

func (s *Service) Speedtest() SpeedtestState {
	stMu.Lock()
	defer stMu.Unlock()
	return SpeedtestState{Running: stRunning, Result: stResult, Error: stError}
}

func (s *Service) MeasuredMbit() (down, up int) {
	return atoiSafe(s.setting(SettingMeasuredDown)) / 1000,
		atoiSafe(s.setting(SettingMeasuredUp)) / 1000
}

func (s *Service) Baseline() (downKbit int, at time.Time, direct bool) {
	downKbit = atoiSafe(s.setting(SettingDirectDown))
	if raw := s.setting(SettingDirectAt); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			at = parsed
		}
	}
	return downKbit, at, downKbit > 0
}

func (s *Service) SaveDirectBaseline(downKbit int, at time.Time) {
	if downKbit <= 0 {
		return
	}
	s.setSetting(SettingDirectDown, strconv.Itoa(downKbit))
	s.setSetting(SettingDirectAt, at.Format(time.RFC3339))
}

func (s *Service) currentPath() string {
	resp, err := s.client().Call("vpn.status", map[string]any{})
	if err != nil || resp == nil || resp.Error != nil {
		return ""
	}
	var st struct {
		Mode   string `json:"mode"`
		Online bool   `json:"online"`
	}
	if json.Unmarshal(resp.Result, &st) != nil {
		return ""
	}
	if st.Mode == "black" && st.Online {
		return ViaTunnel
	}
	return ViaDirect
}
