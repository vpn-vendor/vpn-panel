package controllers

import (
	"strconv"
	"strings"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/middleware"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/http/wizard"
	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overview"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/app/services/setup"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

type SetupController struct {
	service *auth.Service
	qos     *qossvc.Service
	network *network.Service
	limiter *ratelimit.Limiter
}

func NewSetupController() *SetupController {
	return &SetupController{
		service: auth.New(),
		qos:     qossvc.New(),
		network: network.New(),

		limiter: ratelimit.New(5, 1, time.Minute),
	}
}

func (c *SetupController) facts() setup.Facts {
	return setup.Collect(setup.Deps{Paths: func() []pathmon.Snapshot {
		if pm := bootstrapPathMonitor(); pm != nil {
			return pm.Paths()
		}
		return nil
	}})
}

func (c *SetupController) Show(ctx contractshttp.Context) contractshttp.Response {
	if c.service.HasUsers() {
		f := c.facts()
		plan := wizard.Plan(f.Wizard())
		if plan.Current != nil {
			return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/"+plan.Current.Key)
		}
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/check")
	}
	plan := wizard.Plan(wizard.Facts{Set: map[wizard.Fact]bool{}, Cards: 2})
	view := map[string]any{
		"needCode": !middleware.IsLoopback(ctx.Request().Ip()),
		"error":    takeFlash(ctx, flashError),
		"stepper":  stepperOf(plan),
	}

	if code := ctx.Request().Query("code"); codeInURLRe.MatchString(code) {
		view["prefillCode"] = code
	}
	return ctx.Response().View().Make("setup.tmpl", page(ctx, "Установка", "", view))
}

func (c *SetupController) Store(ctx contractshttp.Context) contractshttp.Response {
	if c.service.HasUsers() {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/login")
	}
	ip := ctx.Request().Ip()
	if !c.limiter.Allow(ip) {
		return c.showError(ctx, "Слишком много попыток. Подождите минуту.")
	}

	if !middleware.IsLoopback(ip) && !c.service.CheckSetupCode(ctx.Request().Input("setup_code")) {
		c.service.Audit("setup_denied", nil, nil, ip, "неверный установочный код")
		return c.showError(ctx, "Код не подходит или истёк.")
	}

	name := ctx.Request().Input("name", "Администратор")
	maxUsers, err := strconv.Atoi(ctx.Request().Input("max_users", "1"))
	if err != nil {
		return c.showError(ctx, "Число учётных записей укажите цифрами.")
	}

	if _, err := auth.Edit(func(s *auth.Section) error { s.MaxUsers = maxUsers; return nil }); err != nil {
		return c.showError(ctx, "Настройки не сохранены: "+err.Error()+".")
	}
	user, err := c.service.CreateUser(name)
	if err != nil {
		return c.showError(ctx, "Не удалось создать учётную запись.")
	}
	token, device, err := c.service.EnrollConsoleDevice(user.ID,
		ctx.Request().Input("device_label", "Компьютер установки"),
		ctx.Request().Header("User-Agent"), ip)
	if err != nil {
		return c.showError(ctx, "Не удалось доверить это устройство.")
	}
	c.service.ClearSetupCode()
	c.service.Audit("setup_completed", &user.ID, &device.ID, ip, "учётная запись создана, мастер продолжается")

	setDeviceCookie(ctx, token)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
}

func (c *SetupController) Step(ctx contractshttp.Context) contractshttp.Response {
	key := ctx.Request().Route("step")
	step, ok := wizard.ByKey(key)
	if !ok {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	f := c.facts()
	plan := wizard.Plan(f.Wizard())
	if !wizard.Applicable(step, f.Wizard()) {
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
	}
	prev, _ := plan.Neighbours(key)
	view := map[string]any{
		"error":     takeFlash(ctx, flashError),
		"ok":        takeFlash(ctx, flashCode),
		"agentDown": f.AgentDown,
		"step":      step,
		"stepper":   stepperOf(plan.Viewing(key)),
		"back":      "",
	}
	if prev != "" {
		view["back"] = "/setup/" + prev
	}
	c.fill(ctx, step.Key, f, view)
	return ctx.Response().View().Make("setup/"+step.Key, page(ctx, "Первая настройка: "+step.Title, "", view))
}

func stepperOf(plan wizard.Progress) ui.Stepper {
	s := ui.Stepper{Total: plan.Total, Current: plan.Total}
	for _, p := range plan.Shown() {
		item := ui.StepperItem{Key: p.Key, Title: p.Title, State: string(p.State)}
		if p.State != wizard.StateTodo {
			item.URL = "/setup/" + p.Key
		}
		if p.State == wizard.StateCurrent {
			s.Current = p.Number
		}
		s.Items = append(s.Items, item)
	}
	return s
}

func (c *SetupController) fill(ctx contractshttp.Context, key string, f setup.Facts, view map[string]any) {
	skip := ui.Button{Label: "Пропустить", Kind: "ghost"}
	switch key {
	case "account":
		view["adminName"] = "Администратор"
	case "restore":
		view["fileField"] = ui.FileField{ID: "file", Name: "file", Label: "Файл копии или шаблона", Accept: ".vpnpanel,.json",
			Hint: "Своя копия восстанавливает всё, шаблон — только правила офиса"}
		view["passField"] = ui.Field{ID: "open-password", Name: "password", Label: "Пароль копии", Type: "password",
			Autocomplete: "off", Hint: "Для шаблона не нужен"}
		view["uploadBtn"] = ui.Button{Label: "Загрузить файл"}
		skip.Label = "Нет, настроить заново"
		skip.Kind = "secondary"
	case "wan":
		suggested := f.SuggestWAN()
		chosen := f.WANDraft
		if chosen == "" {
			chosen = suggested
		}
		view["cards"] = f.Cards
		view["choice"] = cardChoice(f, chosen, "")
		view["suggested"] = suggested
		if card, ok := f.Card(suggested); ok {
			switch {
			case card.HasRoute:
				view["why"] = "через неё сервер уже выходит в интернет"
			case len(card.Addresses) > 0:
				view["why"] = "у неё есть адрес от сети"
			default:
				view["why"] = "в неё воткнут кабель"
			}
		}
		view["nextBtn"] = ui.Button{Label: "Дальше"}
	case "lan":
		chosen := f.LANDraft
		if chosen == "" {
			for _, card := range f.Cards {
				if card.Name != f.WANDraft && card.Up {
					chosen = card.Name
					break
				}
			}
		}
		view["choice"] = cardChoice(f, chosen, f.WANDraft)
		view["nextBtn"] = ui.Button{Label: "Дальше"}
	case "provider":
		c.fillProvider(ctx, f, view)
	case "internet":
		c.fillInternet(f, view)
		skip.Label = "Продолжить без интернета"
	case "speed":
		addSpeedtestView(view, c.qos.Speedtest())
		view["speedBack"] = "/setup/speed"
		down, up := "", ""
		if f.MeasuredDown > 0 {
			down, up = strconv.Itoa(f.MeasuredDown), strconv.Itoa(f.MeasuredUp)
		}
		view["downField"] = ui.Field{ID: "qos-down", Name: "down_mbit", Type: "number", Label: "Скачивание, Мбит/с",
			Value: down, Placeholder: "из замера или договора", Min: "1", Max: "10000", Required: true}
		view["upField"] = ui.Field{ID: "qos-up", Name: "up_mbit", Type: "number", Label: "Отдача, Мбит/с",
			Value: up, Placeholder: "из замера или договора", Min: "1", Max: "10000", Required: true}
		view["nextBtn"] = ui.Button{Label: "Сохранить и продолжить"}
		skip.Label = "Настроить позже"
	case "channel":
		view["profileSlug"], view["profileName"] = "", ""
		if f.Profiles > 0 && !f.ChannelSet {
			view["profileSlug"], view["profileName"] = f.ProfileSlug, f.ProfileName
		}
		upload := uploadView()
		accept, _ := upload["Accept"].(string)
		view["nameField"] = ui.Field{ID: "vpn-name", Name: "name", Label: "Название подключения", Placeholder: "например, Основное", MaxLength: 60}
		view["fileField"] = ui.FileField{ID: "config", Name: "config", Label: "Файл подключения", Accept: accept, Required: true,
			Hint: "Файл выдаёт поставщик услуги VPN"}
		view["upload"] = upload
		view["uploadBtn"] = ui.Button{Label: "Загрузить"}
		view["enableBtn"] = ui.Button{Label: "Включить защищённый канал"}
		skip.Label = "Пока без канала"
	case "check":
		view["facts"] = c.summary(f)
		view["finishBtn"] = ui.Button{Label: "Открыть панель"}
	}
	view["skipBtn"] = skip
}

func cardChoice(f setup.Facts, chosen, except string) ui.Choice {
	ch := ui.Choice{Name: "card"}
	for _, card := range f.Cards {
		if card.Name == except {
			continue
		}
		o := ui.ChoiceOption{Value: card.Name, Label: "Карта " + card.Name, Checked: card.Name == chosen}
		if card.Up {
			o.Facts = append(o.Facts, "кабель воткнут")
		} else {
			o.Facts = append(o.Facts, "кабеля нет")
		}
		if len(card.Addresses) > 0 {
			o.Facts = append(o.Facts, "адрес "+card.Addresses[0])
		} else {
			o.Facts = append(o.Facts, "адреса нет")
		}
		if card.HasRoute {
			o.Facts = append(o.Facts, "выход в интернет")
		}
		if card.MAC != "" {
			o.Hint = "MAC " + card.MAC
		}
		ch.Options = append(ch.Options, o)
	}
	return ch
}

func (c *SetupController) fillProvider(ctx contractshttp.Context, f setup.Facts, view map[string]any) {
	wan, lan := f.WANDraft, f.ChosenLAN()
	if f.RolesApplied {
		wan, lan = f.WANName, f.LANName
	}
	view["wanName"], view["lanName"] = wan, lan
	method, cidr, gateway, dns, user, vlan := "dhcp", "", "", "", "", ""
	lanCIDR := f.SuggestLANCIDR()
	if f.RolesApplied {
		method, cidr, gateway, dns, user, vlan = f.WANMethod, f.WANCIDR, f.WANGateway, f.WANDNS, f.PPPoEUser, f.VLAN
		if f.LANCIDR != "" {
			lanCIDR = f.LANCIDR
		}
	}
	if method == "" {
		method = "dhcp"
	}
	view["choice"] = ui.Choice{Name: "wanmethod_" + wan, Options: []ui.ChoiceOption{
		{Value: "dhcp", Label: "Автоматически", Hint: "Провайдер выдаёт адрес сам. Так у большинства.", Checked: method == "dhcp"},
		{Value: "static", Label: "Постоянный адрес", Hint: "В договоре написаны адрес, маска, шлюз.", Checked: method == "static", Reveals: "static"},
		{Value: "pppoe", Label: "По логину и паролю (PPPoE)", Hint: "Провайдер дал имя пользователя и пароль.", Checked: method == "pppoe", Reveals: "pppoe"},
	}}
	view["ipField"] = ui.Field{ID: "wan-ip", Name: "cidr_" + wan, Label: "IP-адрес", Value: cidr, Placeholder: "203.0.113.45", Autocomplete: "off"}
	view["maskField"] = ui.Field{ID: "wan-mask", Name: "mask", Label: "Маска подсети", Placeholder: "255.255.255.0 или /24", Autocomplete: "off",
		Hint: "Не уверены — впишите адрес и шлюз, панель подскажет"}
	view["gatewayField"] = ui.Field{ID: "wan-gateway", Name: "gateway_" + wan, Label: "Шлюз провайдера", Value: gateway, Placeholder: "203.0.113.1", Autocomplete: "off"}
	view["dnsField"] = ui.Field{ID: "wan-dns", Name: "dns_" + wan, Label: "Серверы имён", Value: dns, Placeholder: "9.9.9.9, 149.112.112.112", Autocomplete: "off", Hint: "Необязательно"}
	view["pppoeUserField"] = ui.Field{ID: "pppoe-user", Name: "pppoeuser_" + wan, Label: "Имя пользователя", Value: user, Placeholder: "user@provider", Autocomplete: "off"}
	view["pppoePassField"] = ui.Field{ID: "pppoe-pass", Name: "pppoepass_" + wan, Label: "Пароль", Type: "password", Autocomplete: "new-password", Placeholder: "пароль от провайдера"}
	view["vlanField"] = ui.Field{ID: "wan-vlan", Name: "vlan_" + wan, Label: "Тег VLAN", Value: vlan, Placeholder: "например 100", Autocomplete: "off", Hint: "Пусто — без тега"}
	view["lanField"] = ui.Field{ID: "lan-cidr", Name: "cidr_" + lan, Label: "Адрес шлюза в офисе", Value: lanCIDR, Autocomplete: "off", Required: true}
	view["timeout"] = f.ConfirmTimeout
	view["applyBtn"] = ui.Button{Label: "Применить и проверить"}

	ip := ""
	if ctx != nil {
		ip = ctx.Request().Ip()
	}
	if card, ok := f.Card(wan); ok && setup.InSameNet(card, ip) {
		view["lockout"] = "Вы подключены к панели через карту «" + wan + "», которая станет картой в интернет: после применения панель на ней недоступна. Примените настройки с самого сервера или из сети офиса."
	} else if card, ok := f.Card(lan); ok && setup.InSameNet(card, ip) {
		view["lockout"] = "Вы подключены через карту «" + lan + "» из сети " + card.Addresses[0] + ". После применения у неё будет адрес " + lanCIDR + ": чтобы панель не потеряла вас, укажите адрес из вашей сети ниже или примените настройки с самого сервера."
	}
}

func (c *SetupController) fillInternet(f setup.Facts, view map[string]any) {
	var paths []pathmon.Snapshot
	if pm := bootstrapPathMonitor(); pm != nil {
		paths = pm.Paths()
	}
	light := overview.Internet(false, paths)
	items := []ui.Fact{{Label: "Интернет", Value: light.Text, Note: light.Advice,
		Judged: ui.Judge(ui.Level(light.Level), light.Owner)}}
	if card, ok := f.Card(f.WANName); ok {
		addr := ""
		if len(card.Addresses) > 0 {
			addr = card.Addresses[0]
		}
		route := "нет"
		if card.HasRoute {
			route = "есть"
		}
		items = append(items, ui.Fact{Label: "Карта в интернет", Value: card.Name},
			ui.Fact{Label: "Адрес от провайдера", Value: addr, Note: "Пусто — провайдер адрес не выдал: проверьте кабель и способ подключения"},
			ui.Fact{Label: "Маршрут в интернет", Value: route})
	}
	view["facts"] = ui.Facts{Title: "Что известно", Items: items}
}

func (c *SetupController) summary(f setup.Facts) ui.Facts {
	yesNo := func(ok bool, yes, no string) (string, ui.Judgment) {
		if ok {
			return yes, ui.Judge(ui.OK, "мастер")
		}
		return no, ui.Judge(ui.Warn, "мастер")
	}
	internet, j1 := yesNo(f.Internet == "up", "работает", "не отвечает")
	if f.Internet == "" {
		internet, j1 = "ещё проверяется", ui.Judgment{}
	}
	speed, j2 := yesNo(f.SpeedSet, "настроен", "не настроен")
	channel, j3 := yesNo(f.ChannelSet, "включён", "не включён — офис выходит напрямую")
	if f.ChannelSet && !f.ChannelUp {
		channel, j3 = "включён, но не отвечает", ui.Judge(ui.Bad, "мастер")
	}
	lan := f.LANName
	if f.LANCIDR != "" {
		lan += " (" + strings.TrimSuffix(f.LANCIDR, "/24") + ")"
	}
	return ui.Facts{Title: "Шлюз настроен", Items: []ui.Fact{
		{Label: "Карта в интернет", Value: f.WANName},
		{Label: "Карта в офис", Value: lan, Note: "Устройства офиса получают адреса и интернет автоматически"},
		{Label: "Интернет", Value: internet, Judged: j1},
		{Label: "Устройств в офисе получили адрес", Value: strconv.Itoa(f.Leases)},
		{Label: "Приоритет разговоров", Value: speed, Judged: j2, Note: "Раздел «QoS»"},
		{Label: "Защищённый канал", Value: channel, Judged: j3, Note: "Раздел «VPN»"},
	}}
}

func (c *SetupController) Answer(ctx contractshttp.Context) contractshttp.Response {
	key, action := ctx.Request().Input("step"), ctx.Request().Input("action")
	f := c.facts()
	var err error
	switch action {
	case "choose":
		card := ctx.Request().Input("card")
		switch key {
		case "wan":
			err = setup.ChooseWAN(f, card)
		case "lan":
			err = setup.ChooseLAN(f, card)
		default:
			err = setup.ErrUnknownStep
		}
	case "skip":
		if step, ok := wizard.ByKey(key); ok && step.Optional {
			err = setup.Skip(key)
		} else {
			err = setup.ErrUnknownStep
		}
	case "finish":
		err = setup.Finish()
		if err == nil {
			c.service.Audit("setup_finished", nil, nil, ctx.Request().Ip(), "мастер закрыт человеком")
			return ctx.Response().Redirect(contractshttp.StatusFound, "/")
		}
	default:
		err = setup.ErrUnknownStep
	}
	if err != nil {
		setFlash(ctx, flashError, err.Error())
		if _, ok := wizard.ByKey(key); ok {
			return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/"+key)
		}
	}
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
}

func (c *SetupController) SpeedStore(ctx contractshttp.Context) contractshttp.Response {
	downMbit, derr := strconv.Atoi(ctx.Request().Input("down_mbit"))
	upMbit, uerr := strconv.Atoi(ctx.Request().Input("up_mbit"))
	if derr != nil || uerr != nil {
		setFlash(ctx, flashError, "Укажите обе скорости числом в Мбит/с — проще всего нажать «Запустить замер» и затем «Подставить».")
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/speed")
	}

	if _, err := qossvc.Edit(func(s *qossvc.Section) error {
		s.Enabled, s.DownKbit, s.UpKbit = true, downMbit*1000, upMbit*1000
		return nil
	}); err != nil {
		setFlash(ctx, flashError, err.Error())
		return ctx.Response().Redirect(contractshttp.StatusFound, "/setup/speed")
	}
	setFlash(ctx, flashCode, "Приоритет телефонии настроен: звонки идут вперёд закачек.")
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
}

func (c *SetupController) showError(ctx contractshttp.Context, msg string) contractshttp.Response {
	setFlash(ctx, flashError, msg)
	return ctx.Response().Redirect(contractshttp.StatusFound, "/setup")
}

func fromWizard(ctx contractshttp.Context) bool { return ctx.Request().Input("wizard") == "1" }

func landing(ctx contractshttp.Context, page string) string {
	if fromWizard(ctx) {
		return "/setup"
	}
	return page
}

func clearDeviceCookie(ctx contractshttp.Context) {
	ctx.Response().Cookie(contractshttp.Cookie{
		Name: auth.DeviceCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: "Strict",
	})
}

func setDeviceCookie(ctx contractshttp.Context, token string) {
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     auth.DeviceCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int((14 * 24 * time.Hour).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
	})
}
