package diag

import (
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/cgroupstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagfacts"
	"github.com/vpn-vendor/vpn-panel-core/internal/diagnose"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/oui"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	SettingActiveProbes = "diag.active_probes"
	SettingSelfLabel    = "diag.self_label"
	SettingLastProbe    = "diag.last_probe"
)

type Service struct {
	dhcp *dhcp.Service
}

func New() *Service { return &Service{dhcp: dhcp.New()} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

type Settings struct {
	ActiveProbes bool
	SelfLabel    bool
}

func (s *Service) Settings() Settings {
	return Settings{
		ActiveProbes: s.setting(SettingActiveProbes, "1") == "1",
		SelfLabel:    s.setting(SettingSelfLabel, "1") == "1",
	}
}

func (s *Service) LANs() []diagnose.LAN {
	var out []diagnose.LAN
	for _, r := range s.dhcp.LANSegments() {
		if r.IPv4CIDR != "" {
			lan := diagnose.LAN{Name: r.Name, CIDR: r.IPv4CIDR}
			if from, to, err := keagen.PoolFor(r.IPv4CIDR); err == nil {
				lan.PoolFrom, lan.PoolTo = from, to
			}
			out = append(out, lan)
		}
	}
	return out
}

func lanNames(lans []diagnose.LAN) []string {
	names := make([]string, 0, len(lans))
	for _, l := range lans {
		names = append(names, l.Name)
	}
	return names
}

func (s *Service) Facts(lans []diagnose.LAN) (*diagfacts.Facts, error) {
	resp, err := s.client().Call("diag.facts", map[string]any{"lans": lanNames(lans)})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var f diagfacts.Facts
	if err := json.Unmarshal(resp.Result, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

type ProbeSnapshot struct {
	At      time.Time                        `json:"at"`
	Results map[string]diagfacts.ProbeResult `json:"results"`
	Partial bool                             `json:"partial"`
}

func (s *Service) LastProbe() ProbeSnapshot {
	var snap ProbeSnapshot
	if raw := s.setting(SettingLastProbe, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &snap)
	}
	if snap.Results == nil {
		snap.Results = map[string]diagfacts.ProbeResult{}
	}
	return snap
}

type Row struct {
	diagnose.Device
	Record models.Device
}

func (s *Service) Report() (*diagnose.Report, []Row, error) {
	lans := s.LANs()
	_, leases, lerr := s.dhcp.Leases()
	facts, err := s.Facts(lans)
	if err != nil {
		return nil, nil, err
	}
	in := diagnose.Input{
		Now: time.Now(), LANs: lans, Neighbours: facts.Neighbours, Sets: facts.Sets, Links: facts.Links,
		Vendor: oui.Vendor, Randomized: oui.Randomized,
	}
	if lerr == nil {
		for _, l := range leases {
			in.Leases = append(in.Leases, diagnose.Lease{IP: l.Address, MAC: l.MAC, Hostname: l.Hostname, Until: l.Until})
		}
	}
	snap := s.LastProbe()
	in.Probe, in.ProbedAt = snap.Results, snap.At
	report := diagnose.Run(in)
	rows := make([]Row, 0, len(report.Devices))
	for _, d := range report.Devices {
		rows = append(rows, Row{Device: d, Record: s.touch(d)})
	}
	return &report, rows, nil
}

var (
	seenMu     sync.Mutex
	seen       = map[string]seenMark{}
	newDevices = ratelimit.New(retention.NewDevicesPerHour, retention.NewDevicesPerHour, time.Hour)
)

const seenMaxKeys = 4096

type seenMark struct {
	wrote    time.Time
	ip, host string
}

func needsWrite(mark seenMark, known bool, row models.Device, d diagnose.Device, now time.Time) bool {
	switch {
	case !known:
		return true
	case d.IP != row.LastIP || (d.Hostname != "" && d.Hostname != row.Hostname):
		return true
	default:
		return now.Sub(mark.wrote) >= retention.DeviceWriteEvery
	}
}

func remember(d diagnose.Device, now time.Time) {
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) >= seenMaxKeys {
		seen = map[string]seenMark{}
	}
	seen[d.MAC] = seenMark{wrote: now, ip: d.IP, host: d.Hostname}
}

func (s *Service) touch(d diagnose.Device) models.Device {
	var row models.Device
	_ = facades.Orm().Query().Where("mac", d.MAC).First(&row)
	now := time.Now()
	if row.ID == 0 {

		if !newDevices.Allow("new") {
			s.Audit("devices_new_throttled", d.IP, "слишком много новых устройств за час — паспорт не заведён")
			return models.Device{MAC: d.MAC, Hostname: d.Hostname, LastIP: d.IP, FirstSeenAt: now, LastSeenAt: now}
		}
		row = models.Device{MAC: d.MAC, Hostname: d.Hostname, LastIP: d.IP,
			FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now}
		_ = facades.Orm().Query().Create(&row)
		remember(d, now)
		return row
	}
	seenMu.Lock()
	mark, known := seen[d.MAC]
	seenMu.Unlock()
	if !needsWrite(mark, known, row, d, now) {
		if d.Online {
			row.LastSeenAt = now
		}
		return row
	}
	remember(d, now)
	updates := map[string]any{"last_ip": d.IP, "updated_at": now}
	if d.Online {
		updates["last_seen_at"] = now
	}
	if d.Hostname != "" {
		updates["hostname"] = d.Hostname
	}
	_, _ = facades.Orm().Query().Model(&models.Device{}).Where("id", row.ID).Update(updates)
	_ = facades.Orm().Query().Where("id", row.ID).First(&row)
	return row
}

var (
	probeMu      sync.Mutex
	probeRunning bool
	probeError   string
	probeDone    time.Time
)

type ProbeState struct {
	Running bool
	Error   string
	Done    time.Time
}

func (s *Service) ProbeState() ProbeState {
	probeMu.Lock()
	defer probeMu.Unlock()
	return ProbeState{Running: probeRunning, Error: probeError, Done: probeDone}
}

func (s *Service) StartProbe(ip string) error {
	if !s.Settings().ActiveProbes {
		return errors.New("активные проверки выключены в настройках диагностики")
	}
	if len(s.LANs()) == 0 {
		return errors.New("нет карт с ролью «локальная сеть» — назначьте роли на странице «Сеть»")
	}
	probeMu.Lock()
	if probeRunning {
		probeMu.Unlock()
		return errors.New("проверка уже идёт — дождитесь результата")
	}
	probeRunning, probeError = true, ""
	probeMu.Unlock()
	go func() {
		started := time.Now()
		snap, err := s.Probe()
		probeMu.Lock()
		defer probeMu.Unlock()
		probeRunning, probeDone = false, time.Now()
		if err != nil {
			probeError = agentrpc.Human(err)
			s.Audit("diag_probe_failed", ip, probeError)
			return
		}
		s.Audit("diag_probe", ip, "опрошено устройств: "+strconv.Itoa(len(snap.Results))+" за "+strconv.Itoa(int(time.Since(started).Seconds()))+" с")
	}()
	return nil
}

func (s *Service) Probe() (ProbeSnapshot, error) {
	if !s.Settings().ActiveProbes {
		return ProbeSnapshot{}, errors.New("активные проверки выключены в настройках диагностики")
	}
	lans := s.LANs()
	if len(lans) == 0 {
		return ProbeSnapshot{}, errors.New("нет карт с ролью «локальная сеть» — назначьте роли на странице «Сеть»")
	}
	snap, err := s.probe(lans, "")
	if err != nil {
		return snap, err
	}
	raw, _ := json.Marshal(snap)
	_ = s.setSetting(SettingLastProbe, string(raw))
	return snap, nil
}

func (s *Service) ProbeOne(ip string) (diagfacts.ProbeResult, error) {
	if !s.Settings().ActiveProbes {
		return diagfacts.ProbeResult{}, errors.New("активные проверки выключены в настройках диагностики")
	}
	snap, err := s.probe(s.LANs(), ip)
	if err != nil {
		return diagfacts.ProbeResult{}, err
	}
	if r, ok := snap.Results[ip]; ok {
		return r, nil
	}
	return diagfacts.ProbeResult{}, errors.New("устройство не найдено среди соседей шлюза")
}

func (s *Service) probe(lans []diagnose.LAN, target string) (ProbeSnapshot, error) {
	params := map[string]any{"lans": lanNames(lans)}
	if target != "" {
		params["target"] = target
	}
	resp, err := s.client().Call("diag.probe", params)
	if err != nil {
		return ProbeSnapshot{}, err
	}
	if resp.Error != nil {
		return ProbeSnapshot{}, resp.Error
	}
	var r struct {
		Results     []diagfacts.ProbeResult `json:"results"`
		StartedAt   int64                   `json:"started_at"`
		DeadlineHit bool                    `json:"deadline_hit"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ProbeSnapshot{}, err
	}
	snap := ProbeSnapshot{At: time.Unix(r.StartedAt, 0), Results: map[string]diagfacts.ProbeResult{}, Partial: r.DeadlineHit}
	for _, res := range r.Results {
		snap.Results[res.IP] = res
	}
	return snap, nil
}

type Identity struct {
	IP         string
	MAC        string
	Hostname   string
	Vendor     string
	Segment    string
	LeaseUntil time.Time
	Record     models.Device
	Found      bool
}

func (s *Service) Identify(ip string) Identity {
	id := Identity{IP: ip}
	lans := s.LANs()
	facts, err := s.Facts(lans)
	if err != nil {
		return id
	}
	for _, n := range facts.Neighbours {
		if n.IP == ip {
			id.MAC, id.Segment, id.Found = n.MAC, n.Dev, true
			break
		}
	}
	if !id.Found {
		return id
	}
	if _, leases, err := s.dhcp.Leases(); err == nil {
		for _, l := range leases {
			if l.MAC == id.MAC {
				id.Hostname, id.LeaseUntil = trimDot(l.Hostname), l.Until
			}
		}
	}
	id.Vendor = oui.Vendor(id.MAC)
	id.Record = s.touch(diagnose.Device{MAC: id.MAC, IP: ip, Hostname: id.Hostname, Online: true})
	return id
}

func (s *Service) Propose(id Identity, label, location, owner string) error {
	if !s.Settings().SelfLabel {
		return errors.New("предложения подписей выключены администратором")
	}
	if !id.Found {
		return errors.New("устройство не найдено среди соседей шлюза — подключитесь к локальной сети офиса")
	}
	l, err := ValidateText(label, MaxLabel)
	if err != nil {
		return errors.New("название: " + err.Error())
	}
	loc, err := ValidateText(location, MaxLocation)
	if err != nil {
		return errors.New("где стоит: " + err.Error())
	}
	own, err := ValidateText(owner, MaxOwner)
	if err != nil {
		return errors.New("кому принадлежит: " + err.Error())
	}
	if l == "" && loc == "" && own == "" {
		return errors.New("заполните хотя бы одно поле")
	}
	now := time.Now()
	_, err = facades.Orm().Query().Model(&models.Device{}).Where("id", id.Record.ID).Update(map[string]any{
		"proposed_label": l, "proposed_location": loc, "proposed_owner": own,
		"proposed_ip": id.IP, "proposed_at": now, "updated_at": now,
	})
	if err != nil {
		return errors.New("не удалось сохранить предложение — попробуйте ещё раз")
	}
	s.Audit("device_label_proposed", id.IP, "устройство "+id.MAC+" ("+id.Hostname+") предложило подпись «"+l+"»")
	return nil
}

func (s *Service) Proposals() []models.Device {
	var rows []models.Device
	_ = facades.Orm().Query().Where("proposed_at IS NOT NULL").OrderByDesc("proposed_at").Limit(500).Find(&rows)
	return rows
}

func (s *Service) Accept(mac, ip string) error {
	var row models.Device
	if err := facades.Orm().Query().Where("mac", mac).First(&row); err != nil || row.ID == 0 || row.ProposedAt == nil {
		return errors.New("предложение не найдено")
	}

	public := joinNonEmpty(row.ProposedLabel, row.ProposedLocation, row.ProposedOwner)
	if len([]rune(public)) > MaxPublicLabel {
		public = row.ProposedLabel
	}
	if _, err := EditLabels("proposal", func(v *LabelsSection) error {
		l := labelOf(v, mac)
		l.Label, l.Location, l.Owner, l.PublicLabel = row.ProposedLabel, row.ProposedLocation, row.ProposedOwner, public
		return nil
	}); err != nil {
		return err
	}
	if _, err := facades.Orm().Query().Model(&models.Device{}).Where("id", row.ID).Update(clearedProposal()); err != nil {
		return err
	}
	s.Audit("device_label_accepted", ip, "подпись устройства "+mac+": «"+row.ProposedLabel+"»")
	return nil
}

func (s *Service) Reject(mac, ip string) error {
	if _, err := facades.Orm().Query().Model(&models.Device{}).Where("mac", mac).Update(clearedProposal()); err != nil {
		return err
	}
	s.Audit("device_label_rejected", ip, "предложение устройства "+mac+" отклонено")
	return nil
}

func (s *Service) AcceptAll(ip string) int {
	n := 0
	for _, p := range s.Proposals() {
		if s.Accept(p.MAC, ip) == nil {
			n++
		}
	}
	return n
}

type LabelUpdate struct {
	Public, Label, Location, Owner, Note *string
}

func labelFields(u LabelUpdate) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range []struct {
		v      *string
		column string
		max    int
		name   string
	}{
		{u.Public, "public_label", MaxPublicLabel, "видимая подпись"},
		{u.Label, "label", MaxLabel, "название"},
		{u.Location, "location", MaxLocation, "где стоит"},
		{u.Owner, "owner", MaxOwner, "кому принадлежит"},
		{u.Note, "note", MaxNote, "заметка"},
	} {
		if f.v == nil {
			continue
		}
		v, err := ValidateText(*f.v, f.max)
		if err != nil {
			return nil, errors.New(f.name + ": " + err.Error())
		}
		out[f.column] = v
	}
	return out, nil
}

func (s *Service) SetLabel(mac, ip string, u LabelUpdate) error {
	fields, err := labelFields(u)
	if err != nil {
		return err
	}
	var dev models.Device
	if err := facades.Orm().Query().Where("mac", mac).First(&dev); err != nil || dev.ID == 0 {
		return errors.New("устройство не найдено")
	}
	if _, err := EditLabels("admin", func(v *LabelsSection) error {

		l := labelOf(v, mac)
		for col, dst := range map[string]*string{"public_label": &l.PublicLabel, "label": &l.Label,
			"location": &l.Location, "owner": &l.Owner, "note": &l.Note} {
			if v, ok := fields[col]; ok {
				*dst = v.(string)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	what := "подпись устройства " + mac + ":"
	if u.Public != nil {
		what += " видно сотруднику «" + fields["public_label"].(string) + "»"
	}
	if u.Label != nil {
		what += " название «" + fields["label"].(string) + "»"
	}
	s.Audit("device_label_set", ip, what)
	return nil
}

func VisibleLabel(d models.Device) string {
	if d.PublicLabel != "" {
		return d.PublicLabel
	}
	if d.LabelReviewedAt == nil {
		return joinNonEmpty(d.Label, d.Location, d.Owner)
	}
	return ""
}

func joinNonEmpty(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += p
	}
	return out
}

func clearedProposal() map[string]any {
	return map[string]any{"proposed_label": "", "proposed_location": "", "proposed_owner": "", "proposed_ip": "", "proposed_at": nil}
}

const (
	LanTestCooldown = 2 * time.Minute

	LanTestDataGrace = 2 * time.Second

	LanTestLockGrace = 20 * time.Second
)

var (
	ErrLanTestBusy     = errors.New("тест уже идёт с другого компьютера — подождите")
	ErrLanTestExpired  = errors.New("сеанс проверки окончен — запустите проверку заново кнопкой")
	ErrLanTestCooldown = errors.New("перерыв между проверками — попробуйте через пару минут")
)

var (
	lanTestMu    sync.Mutex
	lanTestOwner string
	lanTestData  time.Time
	lanTestUntil time.Time
	lanTestCool  time.Time
	lanTestNext  time.Time

	lanTestThrottleStart uint64
	lanTestThrottleKnown bool
)

func LanTestSession(ip string, d time.Duration) (fresh bool, err error) {
	return lanTestSessionAt(time.Now(), ip, d)
}

func lanTestSessionAt(now time.Time, ip string, d time.Duration) (bool, error) {
	lanTestMu.Lock()
	defer lanTestMu.Unlock()
	if now.Before(lanTestUntil) {
		if lanTestOwner != ip {
			return false, ErrLanTestBusy
		}
		if !now.Before(lanTestData) {
			return false, ErrLanTestExpired
		}
		return false, nil
	}
	if now.Before(lanTestCool) {
		return false, ErrLanTestCooldown
	}
	lanTestOwner = ip
	lanTestData = now.Add(d + LanTestDataGrace)
	lanTestUntil = lanTestData.Add(LanTestLockGrace)
	lanTestCool = now.Add(d + LanTestCooldown)
	lanTestNext = now
	lanTestThrottleStart, lanTestThrottleKnown = cgroupstat.Throttled()
	return true, nil
}

func LanTestReset() {
	lanTestMu.Lock()
	defer lanTestMu.Unlock()
	lanTestOwner = ""
	lanTestData, lanTestUntil, lanTestCool, lanTestNext = time.Time{}, time.Time{}, time.Time{}, time.Time{}
}

func LanTestThrottled(ip string) (throttled, known bool) {
	lanTestMu.Lock()
	defer lanTestMu.Unlock()
	if lanTestOwner != ip || !lanTestThrottleKnown {
		return false, false
	}
	now, ok := cgroupstat.Throttled()
	if !ok {
		return false, false
	}
	return now > lanTestThrottleStart, true
}

func LanTestPace(chunk int, bytesPerSec float64) time.Duration {
	lanTestMu.Lock()
	defer lanTestMu.Unlock()
	now := time.Now()
	wait := lanTestNext.Sub(now)
	if wait < 0 {
		wait = 0
		lanTestNext = now
	}
	lanTestNext = lanTestNext.Add(time.Duration(float64(chunk) / bytesPerSec * float64(time.Second)))
	return wait
}

func (s *Service) SaveLanTest(id Identity, mbit int, idleMs, loadMs float64) error {
	if !id.Found {
		return errors.New("устройство не найдено среди соседей шлюза")
	}
	now := time.Now()
	_, err := facades.Orm().Query().Model(&models.Device{}).Where("id", id.Record.ID).Update(map[string]any{
		"lan_mbit": mbit, "lan_idle_ms": idleMs, "lan_load_ms": loadMs, "lan_tested_at": now, "updated_at": now})
	if err == nil {
		s.Audit("diag_lantest", id.IP, "скорость до шлюза "+strconv.Itoa(mbit)+" Мбит/с, задержка "+formatMs(idleMs)+" → "+formatMs(loadMs)+" мс под нагрузкой")
	}
	return err
}

func formatMs(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func (s *Service) Audit(event, ip, details string) {
	securitylog.Record(models.AuthEvent{Event: event, IP: ip, Details: details, OccurredAt: time.Now()})
}

func trimDot(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		return h[:len(h)-1]
	}
	return h
}

func (s *Service) setting(key, def string) string {
	if v, ok := settings.Value(key); ok {
		return v
	}
	return def
}

func (s *Service) setSetting(key, value string) error { return settings.Set(key, value) }

func boolValue(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

const MaxIdentifyNote = 120

func (s *Service) RequestIdentify(id Identity, note string) error {
	if !s.Settings().SelfLabel {
		return errors.New("сообщения администратору выключены в настройках диагностики")
	}
	if !id.Found {
		return errors.New("устройство не найдено среди соседей шлюза — подключитесь к локальной сети офиса")
	}
	nt, err := ValidateText(note, MaxIdentifyNote)
	if err != nil {
		return errors.New("текст: " + err.Error())
	}
	now := time.Now()
	_, err = facades.Orm().Query().Model(&models.Device{}).Where("id", id.Record.ID).Update(map[string]any{
		"identify_requested_at": now, "identify_note": nt, "identify_ip": id.IP, "identify_segment": id.Segment,
		"identify_count": id.Record.IdentifyCount + 1, "updated_at": now})
	if err != nil {
		return err
	}
	s.Audit("device_identify_requested", id.IP, "устройство "+id.MAC+" ("+id.Hostname+"), сегмент "+id.Segment+
		", сообщений всего "+strconv.Itoa(id.Record.IdentifyCount+1)+"; текст: «"+nt+"»")
	return nil
}

func (s *Service) IdentifyRequests() []models.Device {
	var rows []models.Device
	_ = facades.Orm().Query().Where("identify_requested_at IS NOT NULL").OrderBy("identify_requested_at", "desc").Find(&rows)
	return rows
}

func (s *Service) OpenIdentifyCount() int64 {
	n, _ := facades.Orm().Query().Model(&models.Device{}).Where("identify_requested_at IS NOT NULL").Count()
	return n
}

func (s *Service) CloseIdentify(mac, ip, why string) error {
	res, err := facades.Orm().Query().Model(&models.Device{}).Where("mac", mac).Update(map[string]any{
		"identify_requested_at": nil, "identify_note": "", "identify_ip": "", "identify_segment": "", "updated_at": time.Now()})
	if err != nil {
		return err
	}
	if res.RowsAffected == 0 {
		return errors.New("устройство не найдено")
	}
	s.Audit("device_identify_closed", ip, "устройство "+mac+": "+why)
	return nil
}
