package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/internal/speedtest"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpncheck"
)

const (
	CheckQuick = "quick"
	CheckFull  = "full"

	checkHistoryLimit = 50
)

var (
	chkMu     sync.Mutex
	chkRun    bool
	chkReport *vpncheck.Report
	chkTunnel CheckTunnel
	chkErr    string
)

type CheckTunnel struct {
	Profile, Mode string
	Session       int64
}

func (t CheckTunnel) Current(st *Status) bool {
	return st != nil && t.Session != 0 && t.Session == st.Session.ID && t.Profile == st.Slug && t.Mode == st.Mode
}

type CheckState struct {
	Running bool
	Report  *vpncheck.Report
	Error   string
	Tunnel  CheckTunnel
}

func (s *Service) Check() CheckState {
	chkMu.Lock()
	defer chkMu.Unlock()
	st := CheckState{Running: chkRun, Report: chkReport, Error: chkErr, Tunnel: chkTunnel}
	if st.Report == nil && !st.Running {
		st.Report, st.Tunnel = s.lastCheck()
	}
	return st
}

func (s *Service) StartCheck(mode string, withDirect bool) error {
	if mode != CheckFull {
		mode = CheckQuick
		withDirect = false
	}
	chkMu.Lock()
	defer chkMu.Unlock()
	if chkRun {
		return errors.New("проверка уже идёт — дождитесь результата")
	}
	chkRun = true
	chkReport = nil
	chkErr = ""
	go s.runCheck(mode, withDirect)
	return nil
}

func (s *Service) runCheck(mode string, withDirect bool) {
	report, tunnel, err := s.collect(mode, withDirect)

	chkMu.Lock()
	defer chkMu.Unlock()
	chkRun = false
	if err != nil {
		chkErr = err.Error()
		return
	}
	chkReport, chkTunnel = report, tunnel
	s.saveCheck(report, tunnel)
}

func (s *Service) collect(mode string, withDirect bool) (*vpncheck.Report, CheckTunnel, error) {
	started := time.Now()
	rep := &vpncheck.Report{StartedAt: started, Mode: mode}

	status, err := s.Status()
	if err != nil {
		return nil, CheckTunnel{}, errors.New("системная служба не отвечает — повторите попытку")
	}
	if status.Mode != ModeBlack || !status.Present {
		return nil, CheckTunnel{}, errors.New("проверять нечего: защищённый канал не включён")
	}
	tunnel := CheckTunnel{Profile: status.Slug, Mode: status.Mode, Session: status.Session.ID}
	rep.Cores = status.Cores
	rep.LoadStart = status.Load1

	qosPlan := s.qos.BuildPlan()
	rep.TariffDownKbit = qosPlan.DownKbit
	rep.TariffUpKbit = qosPlan.UpKbit
	rep.ShapedTunDownKbit = qosPlan.TunnelDownKbit()
	rep.ShapedTunUpKbit = qosPlan.TunnelUpKbit()

	before, beforeErr := s.queueDrops()

	var loadDone chan *vpncheck.Speed
	if mode == CheckFull {
		rep.UnderLoad = true
		loadDone = make(chan *vpncheck.Speed, 1)
		go func() { loadDone <- s.measureSpeed() }()
		time.Sleep(5 * time.Second)
	}

	rxBefore := int64(0)
	if st, err := s.Status(); err == nil {
		rxBefore = st.RxBytes
	}

	probes, perr := s.measure()
	if st, err := s.Status(); err == nil && rxBefore > 0 && st.RxBytes > rxBefore {
		rep.LoadBytes = st.RxBytes - rxBefore
	}
	if perr != nil {
		rep.Notes = append(rep.Notes, "пробы канала: "+perr.Error())
	} else {
		rep.DirectLeg = probes.DirectLeg.probe(vpncheck.KindEcho,
			"Задержка до сервера подключения мимо канала", "сервер подключения")
		rep.TunnelLeg = probes.TunnelLeg.probe(vpncheck.KindEcho,
			"Задержка до того же сервера внутри канала", "сервер подключения")
		rep.Service = probes.Service.probe(vpncheck.KindEcho,
			"Служебные пакеты через канал", "сервер имён")
		rep.Data = probes.Data.probe(vpncheck.KindConnection,
			"Настоящие данные через канал", "сервер имён")
		rep.Large = probes.Large.probe(vpncheck.KindSize,
			"Крупные пакеты через канал", "сервер имён")
		if probes.Load1 > rep.LoadStart {
			rep.LoadStart = probes.Load1
		}
	}

	if loadDone != nil {
		select {
		case rep.Speed = <-loadDone:
			if withDirect && rep.Speed != nil {
				s.measureDirectLeg(rep)
			}
		case <-time.After(90 * time.Second):
			rep.Notes = append(rep.Notes, "замер скорости не завершился в отведённое время")
		}
	}

	after, afterErr := s.queueDrops()
	rep.Queue = vpncheck.QueueDrops{ByName: map[string]int64{}}
	switch {
	case beforeErr != nil || afterErr != nil:
		rep.Queue.Err = "счётчики очередей прочитать не удалось"
	default:
		for dev, n := range after {
			delta := n - before[dev]
			if delta < 0 {
				delta = 0
			}
			rep.Queue.ByName[dev] = delta
			rep.Queue.Total += delta
		}
	}

	if st, serr := s.Status(); serr == nil {
		rep.LoadEnd = st.Load1
	}
	if rep.UnderLoad && !rep.LoadOK() {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"закачка во время проб не состоялась (через канал прошло %d МБ) — выводы о работе под нагрузкой недействительны, повторите проверку",
			rep.LoadMB()))
	}
	rep.Took = time.Since(started)

	if end, err := s.Status(); err != nil || end.Session.ID != tunnel.Session {
		tunnel.Session = 0
	}
	return rep, tunnel, nil
}

type measureItem struct {
	Stats    vpncheck.Stats `json:"stats"`
	Err      string         `json:"err"`
	Fallback bool           `json:"fallback"`
}

type measureResult struct {
	Cores     int         `json:"cores"`
	Load1     float64     `json:"load1"`
	DirectLeg measureItem `json:"direct_leg"`
	TunnelLeg measureItem `json:"tunnel_leg"`
	Service   measureItem `json:"service"`
	Data      measureItem `json:"data"`
	Large     measureItem `json:"large"`
}

func (m measureItem) probe(kind vpncheck.Kind, title, target string) vpncheck.Probe {
	p := vpncheck.Probe{Kind: kind, Title: title, Target: target, Stats: m.Stats, Err: m.Err}
	if m.Fallback {
		p.Target = "узел замера скорости"
	}
	if p.Err != "" {
		p.Note = vpncheck.SampleNote(kind, 0)
	} else {
		p.Note = vpncheck.SampleNote(kind, m.Stats.Sent)
	}
	return p
}

func (s *Service) measure() (*measureResult, error) {
	resp, err := s.client().Call("vpn.measure", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, errors.New(resp.Error.Message)
	}
	deadline := time.Now().Add(measureWait)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		got, gerr := s.client().Call("vpn.measure_get", map[string]any{})
		if gerr != nil {
			return nil, gerr
		}
		if got.Error != nil {
			return nil, errors.New(got.Error.Message)
		}
		var out struct {
			measureResult
			Running bool   `json:"running"`
			Err     string `json:"err"`
		}
		if uerr := json.Unmarshal(got.Result, &out); uerr != nil {
			return nil, uerr
		}
		if out.Running {
			continue
		}
		if out.Err != "" {
			return nil, errors.New(out.Err)
		}
		res := out.measureResult
		return &res, nil
	}
	return nil, errors.New("пробы канала не завершились в отведённое время")
}

const measureWait = 90 * time.Second

func (s *Service) measureSpeed() *vpncheck.Speed {
	sp := &vpncheck.Speed{}

	if kbit, at, direct := s.qos.Baseline(); direct {
		sp.BaselineDownKbit, sp.BaselineAt = kbit, at
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := speedtest.New().MeasureDown(ctx)
	if err != nil {
		sp.Err = "скорость через канал измерить не удалось: " + err.Error()
		return sp
	}
	sp.TunnelDownKbit = res.DownKbit
	for _, src := range res.Down {
		if src.Kbit > 0 {
			sp.Sources = append(sp.Sources, src.Name)
		}
	}
	return sp
}

func (s *Service) measureDirectLeg(rep *vpncheck.Report) {
	resp, err := s.client().Call("vpn.speed_direct", map[string]any{})
	if err != nil {
		rep.Speed.DirectErr = "прямое плечо измерить не удалось: системная служба не ответила"
		return
	}
	if resp.Error != nil {
		rep.Speed.DirectErr = "прямое плечо измерить не удалось: " + resp.Error.Message
		return
	}
	var out struct {
		DownKbit int    `json:"down_kbit"`
		Source   string `json:"source"`
	}
	if json.Unmarshal(resp.Result, &out) != nil || out.DownKbit <= 0 {
		rep.Speed.DirectErr = "прямое плечо измерить не удалось: источник не ответил"
		return
	}
	now := time.Now()
	rep.Speed.BaselineDownKbit = out.DownKbit
	rep.Speed.BaselineAt = now
	rep.Speed.BaselineFresh = true
	rep.Speed.BaselineSource = out.Source

	s.qos.SaveDirectBaseline(out.DownKbit, now)
}

func (s *Service) queueDrops() (map[string]int64, error) {
	resp, err := s.client().Call("qos.counters", map[string]any{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, errors.New(resp.Error.Message)
	}
	var out struct {
		Drops map[string]int64 `json:"drops"`
	}
	if uerr := json.Unmarshal(resp.Result, &out); uerr != nil {
		return nil, uerr
	}
	if out.Drops == nil {
		out.Drops = map[string]int64{}
	}
	return out.Drops, nil
}

func (s *Service) saveCheck(rep *vpncheck.Report, tunnel CheckTunnel) {
	blob, err := json.Marshal(rep)
	if err != nil {
		return
	}
	if err := facades.Orm().Query().Create(&models.VPNCheck{
		Mode: rep.Mode, Report: string(blob), CreatedAt: time.Now(),
		TunnelProfile: tunnel.Profile, TunnelMode: tunnel.Mode, TunnelSession: tunnel.Session,
	}); err != nil {
		log.Printf("vpn: прогон проверки не сохранён: %v", err)
		return
	}

	var old []models.VPNCheck
	if err := facades.Orm().Query().OrderByDesc("id").Offset(checkHistoryLimit).
		Limit(1000).Find(&old); err != nil || len(old) == 0 {
		return
	}
	for _, row := range old {
		_, _ = facades.Orm().Query().Where("id", row.ID).Delete(&models.VPNCheck{})
	}
}

func (s *Service) lastCheck() (*vpncheck.Report, CheckTunnel) {
	var row models.VPNCheck
	if err := facades.Orm().Query().OrderByDesc("id").First(&row); err != nil || row.ID == 0 {
		return nil, CheckTunnel{}
	}
	var rep vpncheck.Report
	if json.Unmarshal([]byte(row.Report), &rep) != nil {
		return nil, CheckTunnel{}
	}
	return &rep, CheckTunnel{Profile: row.TunnelProfile, Mode: row.TunnelMode, Session: row.TunnelSession}
}

func (s *Service) IdleDataLoss(st *Status) float64 {
	if st == nil || st.Session.ID == 0 {
		return 0
	}
	var rows []models.VPNCheck
	if err := facades.Orm().Query().Where("tunnel_session", st.Session.ID).Where("tunnel_profile", st.Slug).
		Where("tunnel_mode", st.Mode).OrderByDesc("id").Limit(checkHistoryLimit).Find(&rows); err != nil {
		return 0
	}
	for i := range rows {
		var rep vpncheck.Report
		if json.Unmarshal([]byte(rows[i].Report), &rep) != nil {
			continue
		}
		if rep.UnderLoad || rep.Data.Err != "" || rep.Data.Stats.Sent == 0 {
			continue
		}
		return rep.Data.Stats.LossPct
	}
	return 0
}

func (s *Service) CheckHistory(limit int) []*vpncheck.Report {
	if limit <= 0 || limit > checkHistoryLimit {
		limit = checkHistoryLimit
	}
	var rows []models.VPNCheck
	if err := facades.Orm().Query().OrderByDesc("id").Limit(limit).Find(&rows); err != nil {
		return nil
	}
	out := make([]*vpncheck.Report, 0, len(rows))
	for i := range rows {
		var rep vpncheck.Report
		if json.Unmarshal([]byte(rows[i].Report), &rep) == nil {
			out = append(out, &rep)
		}
	}
	return out
}
