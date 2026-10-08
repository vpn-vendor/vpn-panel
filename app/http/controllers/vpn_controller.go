package controllers

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	dnssvc "github.com/vpn-vendor/vpn-panel-core/app/services/dns"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	vpnsvc "github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpncheck"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndiag"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

const (
	vpnWeakCPUMbit          = 200
	vpnWeakCPUUserspaceMbit = 100
)

const vpnMaxConfigBytes = 64 * 1024

type VpnController struct {
	service *vpnsvc.Service
	network *network.Service
}

func NewVpnController() *VpnController {
	return &VpnController{service: vpnsvc.New(), network: network.New()}
}

type profileView struct {
	Slug       string
	Name       string
	Endpoint   string
	Addresses  string
	Active     bool
	FullTunnel bool
	ConfigDNS  string
	ConfigMTU  int

	Protocol  string
	Transport string
	VoiceFit  bool
}

func protocolLabel(p string) string {
	if d, ok := vpnproto.Lookup(vpnproto.Stored(p)); ok {
		return d.Label
	}
	return p
}

type uploadKind struct {
	Sep, Label, Ext string
}

func uploadView() map[string]any {
	all := vpnproto.All()
	kinds := make([]uploadKind, 0, len(all))
	for i, d := range all {
		sep := ", "
		switch {
		case i == 0:
			sep = ""
		case i == len(all)-1:
			sep = " и "
		}
		kinds = append(kinds, uploadKind{Sep: sep, Label: d.Label, Ext: d.FileExts[0]})
	}
	return map[string]any{"Accept": strings.Join(append(vpnproto.FileExts(), "text/plain"), ","), "Kinds": kinds}
}

func transportLabel(t string) string {
	if t == vpndriver.TransportTCP {
		return "TCP"
	}
	return "UDP"
}

func (c *VpnController) Index(ctx contractshttp.Context) contractshttp.Response {
	settings := c.service.Load()
	profiles := c.service.Profiles()

	rows := make([]profileView, 0, len(profiles))
	for _, p := range profiles {
		endpoint := p.EndpointHost
		if p.EndpointPort > 0 {
			endpoint = fmt.Sprintf("%s:%d", p.EndpointHost, p.EndpointPort)
		}
		addresses := p.Addresses
		if pp, ok := vpnproto.Passport(vpnproto.Stored(p.Protocol), p.Transport); addresses == "" && ok && !pp.AddressAtImport {
			addresses = "назначает сервер"
		}
		rows = append(rows, profileView{
			Slug: p.Slug, Name: p.Name, Endpoint: endpoint, Addresses: addresses,
			Active: p.Slug == settings.ActiveSlug, FullTunnel: p.FullTunnel,
			ConfigDNS: p.ConfigDNS, ConfigMTU: p.ConfigMTU,
			Protocol: protocolLabel(p.Protocol), Transport: transportLabel(p.Transport),

			VoiceFit: p.VoiceFit && vpndriver.VoiceFit(p.Transport),
		})
	}

	view := map[string]any{
		"error":      takeFlash(ctx, flashError),
		"ok":         takeFlash(ctx, flashCode),
		"profiles":   rows,
		"hasProfile": len(rows) > 0,
		"black":      settings.Mode == vpnsvc.ModeBlack,
		"strict":     settings.OnFailure == vpnsvc.FailStrict,
		"dnsConfig":  settings.DNSChoice == vpnsvc.DNSConfig,
		"mtu":        settings.MTU,
		"minMTU":     vpndriver.MinMTU,
		"maxMTU":     vpndriver.MaxMTU,
		"rolesReady": c.network.HasWANAndLAN(),
		"agentDown":  false,
	}
	var notices []notice

	if !c.network.HasWANAndLAN() {
		notices = append(notices, notice{Level: "info",
			Text: "VPN включится вместе с ролями сетевых карт: назначьте на странице «Сеть», какая карта смотрит в интернет, а какая — в офис."})
	}
	if len(rows) == 0 {

		notices = append(notices, notice{Level: "info",
			Text: "Подключений пока нет. Загрузите файл подключения — его выдаёт поставщик услуги. Панель не создаёт подключения сама: файл всегда приходит от поставщика."})
	}

	st, err := c.service.Status()
	switch {
	case devmode.Enabled:

	case err != nil:
		var terr *agentrpc.TransportError
		if errors.As(err, &terr) {
			view["agentDown"] = true
		} else {
			notices = append(notices, notice{Level: "warn",
				Text: "Не удалось прочитать состояние защищённого канала. Обновите страницу; если повторяется — обратитесь в поддержку."})
		}
	default:
		notices = append(notices, c.statusView(view, settings, st)...)
	}

	view["notices"] = notices
	view["upload"] = uploadView()
	c.pathView(view, settings.ActiveSlug)
	return ctx.Response().View().Make("vpn.tmpl", page(ctx, "VPN", "vpn", view))
}

func (c *VpnController) statusView(view map[string]any, settings vpnsvc.Settings, st *vpnsvc.Status) []notice {
	view["tunnelUp"] = st.Present
	view["online"] = st.Online
	if st.IntentBroken {
		view["intentBroken"] = true
	}
	view["appliedMTU"] = st.MTU
	view["endpointIP"] = st.EndpointIP
	view["endpoint"] = st.Endpoint
	view["cores"] = st.Cores
	view["load1"] = st.Load1
	view["rxText"] = bytesText(st.RxBytes)
	view["txText"] = bytesText(st.TxBytes)
	if st.Online {
		view["handshakeAgo"] = st.HandshakeS
	}
	view["appliedBlack"] = st.Mode == vpnsvc.ModeBlack
	view["dataOK"] = st.DataPlane.IsYes()
	view["dataUnknown"] = !st.DataPlane.Known()
	view["protocol"] = protocolLabel(st.Protocol)
	view["transport"] = transportLabel(st.Transport)
	view["kernelDataPlane"] = st.KernelDataPlane
	view["serverPushed"] = st.ServerPushed

	check := c.service.Check()
	view["checkRunning"] = check.Running
	view["checkError"] = check.Error

	current := check.Tunnel.Current(st)
	view["check"] = checkView(check.Report, !current)
	var rep *vpncheck.Report
	if current {
		rep = check.Report
	}
	view["findings"] = c.findings(settings, st, rep)

	var notices []notice
	switch {
	case st.Degraded:

		text := "VPN не отвечает, и офис сейчас выходит в интернет НАПРЯМУЮ — по вашей настройке «выпускать напрямую». Пока это так, трафик офиса виден провайдеру. Панель повторяет попытки сама"
		if st.RetryInSec > 0 {
			text += fmt.Sprintf(" (следующая через %d с)", st.RetryInSec)
		}
		notices = append(notices, notice{Level: "error", Text: text + "."})
	case st.Mode == vpnsvc.ModeBlack && !st.Online:
		text := "VPN не отвечает. Офис остаётся без интернета — так и задумано: трафик не выпускается мимо канала. Проверьте, что сервер видит интернет, и что подключение у поставщика ещё действует. Панель повторяет попытки сама"
		if st.RetryInSec > 0 {
			text += fmt.Sprintf(" (следующая через %d с)", st.RetryInSec)
		}
		notices = append(notices, notice{Level: "error", Text: text + "."})
	case st.Mode == vpnsvc.ModeBlack && st.Online && st.DataPlane.IsNo():

		notices = append(notices, notice{Level: "error",
			Text: "VPN установлен, но данные через него не проходят. Чаще всего это значит, что файл подключения рассчитан на канал с особыми настройками (например, с маскировкой трафика), которые эта версия панели не поддерживает. Запросите у поставщика обычную конфигурацию. Если файл наш — обратитесь в поддержку, это не поломка вашей сети."})
	case settings.Mode == vpnsvc.ModeBlack && st.Mode != vpnsvc.ModeBlack:
		notices = append(notices, notice{Level: "error",
			Text: "Режим «весь офис через защищённый канал» выбран в настройках, но сейчас не действует. Нажмите «Применить» ещё раз; если не поможет — обратитесь в поддержку."})
	}

	weak := vpnWeakCPUMbit
	if st.Present && !st.KernelDataPlane {
		weak = vpnWeakCPUUserspaceMbit
	}
	if plan := c.network.BuildFirewall(); len(plan.WANs) > 0 && st.Cores > 0 && st.Cores <= 2 {
		if down := c.tariffMbit(); down >= weak {
			notices = append(notices, notice{Level: "warn",
				Text: fmt.Sprintf("Шифрование канала выполняет процессор сервера, а у него %d ядра при скорости тарифа %d Мбит/с. При больших закачках через канал звонки могут пострадать. Рекомендуем более мощный сервер или скорость до %d Мбит/с.",
					st.Cores, down, weak)})
		}
	}
	if st.Present && st.MTU > 0 && settings.MTU == 0 {
		view["mtuAuto"] = true
	}
	return notices
}

func (c *VpnController) findings(settings vpnsvc.Settings, st *vpnsvc.Status, rep *vpncheck.Report) []vpndiag.Finding {
	qos := c.service.QosPlan()
	facts := vpndiag.Facts{
		ModeBlack:         st.Mode == vpnsvc.ModeBlack,
		Present:           st.Present,
		Online:            st.Online,
		DataPlane:         st.DataPlane,
		Degraded:          st.Degraded,
		HandshakeEver:     st.HandshakeS > 0 || st.Online,
		HandshakeAgeSec:   st.HandshakeS,
		Cores:             st.Cores,
		Load1:             st.Load1,
		TariffDownKbit:    qos.DownKbit,
		TariffUpKbit:      qos.UpKbit,
		ShapedTunDownKbit: qos.TunnelDownKbit(),
		ShapedTunUpKbit:   qos.TunnelUpKbit(),
		MTU:               st.MTU,
		BlockedOutbound:   st.BlockedOutbound,
		OutboundGuard:     st.OutboundGuard,
		Protocol:          st.Protocol,
		Transport:         st.Transport,
		KernelDataPlane:   st.KernelDataPlane,
		ProcState:         st.ProcState,
		FailReason:        st.FailReason,
		FailCount:         st.FailCount,
		RetryPaused:       st.RetryPaused,
		SelfHealing:       st.SelfHealing,
		DataStuck:         st.DataDead && st.DataRestartBudget > 0 && st.DataRestarts >= st.DataRestartBudget,
		DataSuspect:       st.DataSuspect,
	}
	if p, ok := c.service.Profile(settings.ActiveSlug); ok {
		facts.FullTunnel = p.FullTunnel
		if settings.DNSChoice == vpnsvc.DNSOurs {
			facts.ConfigDNS = p.ConfigDNS
		}
	}

	if rep != nil {
		loadPeak, serviceLoss, dataLoss, rttBase, rttTunnel, sample,
			dropped, tunnelDown, directDown := rep.Facts()
		facts.ServiceLossPct = serviceLoss
		facts.DataLossPct = dataLoss
		facts.RTTBaselineMs = rttBase
		facts.RTTTunnelMs = rttTunnel
		facts.SampleSize = sample

		facts.SampleMin = vpncheck.MinSamples(vpncheck.KindConnection)

		facts.UnderLoad = rep.LoadOK()

		facts.Blackhole = rep.Blackhole()

		facts.DirectProbed = rep.DirectLeg.Err == "" && rep.DirectLeg.Stats.Sent > 0
		facts.DirectAnswers = facts.DirectProbed && rep.DirectLeg.Stats.Received > 0
		if rep.LoadOK() {
			facts.IdleDataLossPct = c.service.IdleDataLoss(st)
		}
		facts.QueueDropped = dropped
		facts.TunnelDownKbit = tunnelDown
		facts.DirectDownKbit = directDown
		if loadPeak > facts.Load1 {
			facts.Load1 = loadPeak
		}
	}
	return vpndiag.Analyze(facts)
}

func bytesText(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.1f ГБ", float64(n)/(1024*1024*1024))
	case n >= 1024*1024:
		return fmt.Sprintf("%d МБ", n/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%d КБ", n/1024)
	default:
		return fmt.Sprintf("%d байт", n)
	}
}

func (c *VpnController) tariffMbit() int {
	plan := c.service.QosPlan()
	return plan.DownKbit / 1000
}

func (c *VpnController) Import(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	name := strings.TrimSpace(ctx.Request().Input("name"))
	if name == "" {
		name = "Подключение"
	}
	if len([]rune(name)) > 60 {
		name = string([]rune(name)[:60])
	}

	file, err := ctx.Request().File("config")
	if err != nil {
		setFlash(ctx, flashError, "Файл подключения не выбран. Нажмите «Выберите файл» и укажите файл, который выдал поставщик.")
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}

	path := file.File()
	defer func() { _ = os.Remove(path) }()
	if size, serr := file.Size(); serr == nil && size > vpnMaxConfigBytes {
		setFlash(ctx, flashError, "Файл слишком большой для конфигурации подключения — проверьте, что выбран нужный файл.")
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}
	data, rerr := os.ReadFile(path) //nolint:gosec
	if rerr != nil {
		setFlash(ctx, flashError, "Не удалось прочитать выбранный файл. Попробуйте ещё раз.")
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}

	res, ierr := c.service.Import(name, string(data))
	if ierr != nil {
		c.network.Audit("vpn_import_failed", ip, ierr.Error())
		setFlash(ctx, flashError, network.ErrText(ierr))
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}
	c.network.Audit("vpn_import", ip, "профиль: "+res.Slug)

	msg := "Подключение «" + name + "» добавлено."
	if len(res.Warnings) > 0 {

		msg += " Обратите внимание: " + strings.Join(res.Warnings, "; ") + "."
	}
	msg += " Выберите его и нажмите «Применить», чтобы включить."
	setFlash(ctx, flashCode, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
}

func (c *VpnController) Apply(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()

	mtu := 0
	if raw := strings.TrimSpace(ctx.Request().Input("mtu")); raw != "" && raw != "0" {
		n, cerr := strconv.Atoi(raw)
		if cerr != nil {
			setFlash(ctx, flashError, fmt.Sprintf(
				"Размер пакетов должен быть числом от %d до %d. Оставьте поле пустым — панель подберёт его сама.",
				vpndriver.MinMTU, vpndriver.MaxMTU))
			return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
		}
		mtu = n
	}
	want, err := vpnsvc.Edit(func(s *vpnsvc.Section) error {
		s.ActiveSlug, s.Mode, s.OnFailure, s.DNSChoice, s.MTU =
			ctx.Request().Input("profile"), vpnsvc.ModeWhite, vpnsvc.FailStrict, vpnsvc.DNSOurs, mtu
		if ctx.Request().Input("mode") == vpnsvc.ModeBlack {
			s.Mode = vpnsvc.ModeBlack
		}
		if ctx.Request().Input("on_failure") == vpnsvc.FailDirect {
			s.OnFailure = vpnsvc.FailDirect
		}
		if ctx.Request().Input("dns_choice") == vpnsvc.DNSConfig {
			s.DNSChoice = vpnsvc.DNSConfig
		}
		return nil
	})
	if err != nil {
		setFlash(ctx, flashError, "Настройки защищённого канала не сохранены: "+err.Error()+".")
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}
	settings := vpnsvc.Settings{ActiveSlug: want.ActiveSlug, Mode: want.Mode, OnFailure: want.OnFailure,
		MTU: want.MTU, DNSChoice: want.DNSChoice}

	changed, err := c.service.Apply(settings)
	if err != nil {
		var nr *vpnsvc.ErrNotReady
		if errors.As(err, &nr) {
			setFlash(ctx, flashCode, "Настройки сохранены. "+nr.Text)
			return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
		}
		c.network.Audit("vpn_apply_failed", ip, err.Error())
		setFlash(ctx, flashError, "Настройки сохранены, но применить их не удалось: "+network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
	}
	c.network.Audit("vpn_apply", ip, "режим: "+settings.Mode+", при обрыве: "+settings.OnFailure)

	switch {
	case settings.Mode == vpnsvc.ModeWhite:
		setFlash(ctx, flashCode, "Офис выходит в интернет напрямую. Оптимизация телефонии и защита шлюза продолжают работать.")
	case changed:
		setFlash(ctx, flashCode, "Весь офис выходит в интернет через защищённый канал. Если канал пропадёт, интернет в офисе прекратится — так трафик не уйдёт в обход.")
	default:
		setFlash(ctx, flashCode, "Изменений нет — защищённый канал уже работает с этими настройками.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, landing(ctx, "/vpn"))
}

func (c *VpnController) Remove(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	slug := ctx.Request().Input("profile")
	if _, ok := c.service.Profile(slug); !ok {
		setFlash(ctx, flashError, "Подключение не найдено — обновите страницу.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	if err := c.service.Remove(slug); err != nil {
		c.network.Audit("vpn_remove_failed", ip, err.Error())
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	c.network.Audit("vpn_remove", ip, "профиль: "+slug)
	setFlash(ctx, flashCode, "Подключение удалено вместе с его ключом.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
}

func (c *VpnController) TimeSync(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	res, err := c.service.TimeSync()
	if err != nil {
		c.network.Audit("time_sync_failed", ip, err.Error())
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	c.network.Audit("time_sync", ip, fmt.Sprintf("поправка %d с, изменено: %v", res.OffsetSec, res.Changed))

	switch {
	case res.Changed && res.OffsetSec < -60:

		setFlash(ctx, flashCode, fmt.Sprintf(
			"Часы сервера спешили на %s и исправлены; значение записано и в часы платы. "+
				"Важно: пока часы спешили, сервер поставщика запомнил время из будущего и теперь будет отклонять подключение примерно %s — это защита от повторов, а не поломка. "+
				"Канал поднимется сам, когда настоящее время догонит; если ждать нельзя, попросите поставщика перезапустить ваше подключение на его стороне.",
			humanSeconds(-res.OffsetSec), humanSeconds(-res.OffsetSec)))
	case res.Changed:
		setFlash(ctx, flashCode, fmt.Sprintf(
			"Часы сервера были неверны на %s и исправлены. Значение записано и в часы платы, поэтому переживёт перезагрузку. Если канал не поднимался из-за времени — попробуйте включить его снова.",
			humanSeconds(res.OffsetSec)))
	default:
		setFlash(ctx, flashCode, "Часы сервера идут верно — расхождения нет. Значит, причина не во времени.")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
}

func humanSeconds(sec int64) string {
	if sec < 0 {
		sec = -sec
	}
	switch {
	case sec >= 86400:
		return fmt.Sprintf("%d сут", sec/86400)
	case sec >= 3600:
		return fmt.Sprintf("%d ч %d мин", sec/3600, (sec%3600)/60)
	case sec >= 60:
		return fmt.Sprintf("%d мин %d с", sec/60, sec%60)
	default:
		return fmt.Sprintf("%d с", sec)
	}
}

func (c *VpnController) MTUProbe(ctx contractshttp.Context) contractshttp.Response {
	ip := ctx.Request().Ip()
	res, err := c.service.MTUProbe()
	if err != nil {
		c.network.Audit("vpn_mtu_probe_failed", ip, err.Error())
		setFlash(ctx, flashError, network.ErrText(err))
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	c.network.Audit("vpn_mtu_probe", ip, "подобрано: "+strconv.Itoa(res.Recommended))

	if res.Recommended == 0 {
		setFlash(ctx, flashError, "Подобрать размер пакетов не удалось: сервер подключения не отвечает на проверочные пакеты. Оставьте автоподбор — он работает и без этой проверки.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	msg := fmt.Sprintf("Подобранный размер пакетов — %d. Впишите его в поле «Размер пакетов» и нажмите «Применить».", res.Recommended)
	if res.Blackhole {

		msg += " Обнаружена типичная неисправность пути: мелкие пакеты проходят, крупные молча пропадают — из-за неё сайты начинают открываться и «зависают». Подобранный размер это лечит."
	}
	setFlash(ctx, flashCode, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
}

func (c *VpnController) Check(ctx contractshttp.Context) contractshttp.Response {
	mode := vpnsvc.CheckQuick
	if ctx.Request().Input("mode") == vpnsvc.CheckFull {
		mode = vpnsvc.CheckFull
	}

	withDirect := ctx.Request().Input("direct") == "1" && mode == vpnsvc.CheckFull
	if err := c.service.StartCheck(mode, withDirect); err != nil {
		setFlash(ctx, flashError, err.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	if withDirect {
		auth.New().Audit("vpn_direct_probe", nil, nil, ctx.Request().Ip(),
			"замер прямого плеча: сервер вышел в интернет мимо защищённого канала")
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
}

func (c *VpnController) CheckStatus(ctx contractshttp.Context) contractshttp.Response {
	st := c.service.Check()
	return ctx.Response().Json(contractshttp.StatusOK, map[string]any{
		"running": st.Running,
		"error":   st.Error,
	})
}

type probeView struct {
	Title  string
	Target string
	Note   string
	Err    string
	Loss   string
	RTT    string
	Jitter string
	Grade  string
	Why    string
	Burst  string
	OK     bool
}

type checkViewModel struct {
	Has      bool
	Past     bool
	When     string
	Mode     string
	TookSec  int
	Probes   []probeView
	HasSpeed bool
	Speed    string
	Baseline string
	Sources  string
	SpeedErr string
	Queue    string
	Tariff   string
	Ceiling  string
	Cores    int
	Load     string
	Notes    []string
}

func checkView(rep *vpncheck.Report, past bool) checkViewModel {
	if rep == nil {
		return checkViewModel{}
	}
	vm := checkViewModel{
		Has:     true,
		Past:    past,
		When:    rep.StartedAt.Local().Format("02.01.2006 15:04"),
		TookSec: int(rep.Took.Seconds()),
		Cores:   rep.Cores,
		Notes:   rep.Notes,
	}
	vm.Mode = "быстрая"
	if rep.Mode == vpnsvc.CheckFull {
		vm.Mode = "полная"
		if rep.LoadOK() {
			vm.Mode = fmt.Sprintf("полная, под закачкой %d МБ", rep.LoadMB())
		} else {
			vm.Mode = "полная, но закачка не состоялась"
		}
	}
	for _, p := range rep.Probes() {
		row := probeView{Title: p.Title, Target: p.Target, Note: p.Note, Err: p.Err, OK: p.OK()}
		if p.Err == "" && p.Stats.Sent > 0 {
			row.Loss = fmt.Sprintf("%.2f %%", p.Stats.LossPct)

			if p.Stats.AvgMs < 10 {
				row.RTT = fmt.Sprintf("%.1f мс", p.Stats.AvgMs)
			} else {
				row.RTT = fmt.Sprintf("%.0f мс", p.Stats.AvgMs)
			}
			row.Jitter = fmt.Sprintf("%.1f мс", p.Stats.JitterMs)
			grade, why := vpncheck.GradeProbe(p.Kind, p.Stats)
			row.Grade, row.Why = string(grade), why

			if p.Kind != vpncheck.KindSize {
				row.Burst = vpncheck.BurstNote(p.Stats)
			}
		}
		vm.Probes = append(vm.Probes, row)
	}
	if rep.Speed != nil {
		vm.HasSpeed = true
		vm.SpeedErr = rep.Speed.Err
		if rep.Speed.TunnelDownKbit > 0 {
			vm.Speed = fmt.Sprintf("%d Мбит/с", rep.Speed.TunnelDownKbit/1000)
		}
		if rep.Speed.BaselineDownKbit > 0 {
			when := rep.Speed.BaselineAt.Local().Format("02.01.2006")
			if rep.Speed.BaselineFresh {
				vm.Baseline = fmt.Sprintf("%d Мбит/с — измерено сейчас, прямым выходом (%s)",
					rep.Speed.BaselineDownKbit/1000, rep.Speed.BaselineSource)
			} else {
				vm.Baseline = fmt.Sprintf("%d Мбит/с (замер прямым выходом от %s)",
					rep.Speed.BaselineDownKbit/1000, when)
			}
		} else {
			vm.Baseline = "нет: сравнивать не с чем, пока скорость не измерена при прямом доступе в интернет (страница «QoS», режим «Прямой доступ»)"
		}
		vm.Sources = strings.Join(rep.Speed.Sources, ", ")
		if rep.Speed.DirectErr != "" {
			vm.SpeedErr = strings.TrimSpace(vm.SpeedErr + " " + rep.Speed.DirectErr)
		}
	}
	switch {
	case rep.Queue.Err != "":
		vm.Queue = rep.Queue.Err
	case rep.Queue.Total > 0 && rep.Mode == vpnsvc.CheckFull:

		vm.Queue = fmt.Sprintf("%d — это нормально: закачка насыщает канал, и очередь намеренно отбрасывает лишнее, чтобы разговоры шли первыми", rep.Queue.Total)
	case rep.Queue.Total > 0:
		vm.Queue = fmt.Sprintf("%d — очередь отбрасывала пакеты при обычной работе; если это повторяется, тариф в настройках занижен", rep.Queue.Total)
	default:
		vm.Queue = "0 — очереди сервера ничего не отбросили"
	}
	if rep.TariffDownKbit > 0 {
		vm.Tariff = fmt.Sprintf("%d Мбит/с", rep.TariffDownKbit/1000)
		vm.Ceiling = fmt.Sprintf("%d Мбит/с", rep.ShapedTunDownKbit/1000)
	}
	load := rep.LoadStart
	if rep.LoadEnd > load {
		load = rep.LoadEnd
	}
	vm.Load = fmt.Sprintf("%.2f", load)
	return vm
}

type pathRow struct {
	Name, Iface, Targets, Chosen, State, RTT, Loss, Since string
	Up                                                    bool
}

func (c *VpnController) pathView(view map[string]any, slug string) {
	svc := bootstrapPathMonitor()
	if svc == nil {
		return
	}
	view["pathKnown"] = true
	var rows []pathRow
	for _, p := range svc.Paths() {
		r := pathRow{Name: pathKindName(p.Kind), Iface: p.Iface, Targets: strings.Join(p.Targets, ", "), Chosen: p.Chosen,
			State: p.State.String(), Since: p.Since.Local().Format("02.01.2006 15:04:05"), Up: p.State == pathprobe.Up}
		if p.RTT > 0 {
			r.RTT = strconv.FormatFloat(float64(p.RTT)/float64(time.Millisecond), 'f', 1, 64) + " мс"
		}
		if p.LossKnown {
			r.Loss = strconv.FormatFloat(p.LossPct, 'f', 1, 64) + " %"
		} else {
			r.Loss = "мало данных (нужно " + strconv.Itoa(pathprobe.VerdictProbes) + " проб)"
		}
		rows = append(rows, r)
	}
	view["paths"] = rows

	if servers, err := dnssvc.New().Infra(); err == nil && len(servers) > 0 {
		var rows []string
		for _, sv := range servers {
			rows = append(rows, sv.IP+" — "+strconv.FormatFloat(sv.PingMs, 'f', 0, 64)+" мс (разброс "+strconv.FormatFloat(sv.VarMs, 'f', 0, 64)+" мс)")
		}
		view["resolverServers"] = rows
	}
	if rtt, age, ok := svc.Underlay(); rtt > 0 {
		view["underlayRTT"] = strconv.FormatFloat(rtt, 'f', 1, 64)
		view["underlayAge"] = age.Round(time.Minute).String()
		view["underlayFresh"] = ok
	}
	if slug != "" {
		view["fieldProbeTarget"] = ui.Field{ID: "probe-target", Name: "target", Label: "Цель пробы внутри канала (необязательно)",
			Value: c.service.ProbeTarget(slug), Placeholder: "10.8.0.1",
			Hint: "Адрес IPv4 на дальнем конце канала. Пусто — панель выберет сама: адрес, переданный сервером, или первый адрес подсети клиента; кандидат принимается, если отвечает и не дальше публичной цели через канал."}
		view["buttonProbeTarget"] = ui.Button{Label: "Сохранить цель", Kind: "secondary", Small: true}
		view["probeSlug"] = slug
	}
}

func pathKindName(k pathmon.Kind) string {
	switch k {
	case pathmon.Tunnel:
		return "Внутри канала (до сервера канала)"
	case pathmon.Beyond:
		return "За сервером (через канал)"
	case pathmon.Direct:
		return "Прямой доступ"
	}
	return string(k)
}

func (c *VpnController) ProbeTarget(ctx contractshttp.Context) contractshttp.Response {
	slug := ctx.Request().Input("slug")
	if _, ok := c.service.Profile(slug); !ok {
		setFlash(ctx, flashError, "Подключение не найдено.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	target, err := pathmon.ValidateTarget(strings.TrimSpace(ctx.Request().Input("target")))
	if err != nil {
		setFlash(ctx, flashError, "Цель не сохранена: "+err.Error()+".")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	if err := c.service.SetProbeTarget(slug, target); err != nil {
		setFlash(ctx, flashError, "Цель не сохранена.")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
	}
	what := "снята"
	if target != "" {
		what = target
	}
	c.service.Audit("vpn_probe_target", ctx.Request().Ip(), "цель пробы для "+slug+": "+what)
	setFlash(ctx, flashCode, "Цель пробы сохранена: панель пересмотрит её при следующей сверке.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/vpn")
}
