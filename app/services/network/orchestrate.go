package network

import (
	"log"

	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
	dnssvc "github.com/vpn-vendor/vpn-panel-core/app/services/dns"
	qossvc "github.com/vpn-vendor/vpn-panel-core/app/services/qos"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

type Orchestrator struct {
	net  *Service
	dhcp *dhcp.Service
	dns  *dnssvc.Service
	qos  *qossvc.Service
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{net: New(), dhcp: dhcp.New(), dns: dnssvc.New(), qos: qossvc.New()}
}

func (o *Orchestrator) Network() *Service { return o.net }

type Outcome struct {
	AwaitingConfirm bool
	Message         string
}

func (o *Orchestrator) ApplyPlan(ip string, plan netplangen.Plan, st *netstatus.Status, sec ApplySecrets) (*Outcome, error) {
	guard := o.net.GuardNeeded(ip, plan, st)
	if guard {
		if text := o.net.LockoutRisk(ip, plan, st); text != "" {
			o.net.Audit("network_apply_failed", ip, "отказ до применения: администратор потерял бы доступ")
			return nil, &LockoutError{Text: text}
		}
	}
	res, err := o.net.Apply(plan, guard, o.net.FirewallIfReady(), sec)
	if err != nil {
		o.net.Audit("network_apply_failed", ip, err.Error())
		return nil, err
	}
	switch {
	case res.State == "awaiting_confirm":
		o.net.Audit("network_apply", ip, "ожидает подтверждения связи")
		return &Outcome{AwaitingConfirm: true}, nil
	case res.Changed:
		o.net.Audit("network_apply", ip, "применено")
		return &Outcome{Message: "Настройки сети применены." + o.ApplyServices(ip)}, nil
	default:
		return &Outcome{Message: "Изменений нет — настройки уже применены." + o.ApplyServices(ip)}, nil
	}
}

func (o *Orchestrator) Change(ip string, st *netstatus.Status, sec ApplySecrets, edit func() error) (*Outcome, error) {
	changeMu.Lock()
	defer changeMu.Unlock()
	if err := o.net.BeginChange(); err != nil {
		return nil, err
	}
	if err := edit(); err != nil {
		o.settle()
		return nil, err
	}
	out, err := o.ApplyPlan(ip, o.net.BuildPlan(), st, sec)
	if err != nil {
		o.settle()
		return nil, err
	}
	if out.AwaitingConfirm {
		o.net.noteApplied()
		return out, nil
	}
	o.net.CommitChange()
	return out, nil
}

func (o *Orchestrator) settle() {
	if _, err := o.net.settle(false); err != nil {
		log.Printf("network: настройки не приведены к действующим, повтор исполнителем: %v", err)
	}
}

func (o *Orchestrator) Confirm(ip string) (string, error) {
	changeMu.Lock()
	err := o.net.Confirm()
	if err != nil {
		o.settle()
	} else {
		o.net.CommitChange()
	}
	changeMu.Unlock()
	if err != nil {
		o.net.Audit("network_rolled_back", ip, "подтверждение не удалось")
		return "", err
	}
	o.net.Audit("network_confirmed", ip, "изменения закреплены")
	return "Настройки сети применены и закреплены." + o.ApplyServices(ip), nil
}

func (o *Orchestrator) Cancel(ip string) {
	changeMu.Lock()
	_ = o.net.Cancel()
	o.settle()
	changeMu.Unlock()
	o.net.Audit("network_rolled_back", ip, "откат по кнопке")
}

func (o *Orchestrator) ApplyServices(ip string) string {
	if !o.net.HasWANAndLAN() {

		return " Раздача интернета появится, когда назначены и «интернет», и «локальная сеть»." + o.applyQos(ip)
	}

	_, ufw, err := o.net.ApplyFirewall(o.net.BuildFirewall())
	if err != nil {
		o.net.Audit("firewall_apply_failed", ip, err.Error())
		return " Раздать интернет в локальную сеть не удалось: " + ErrText(err)
	}
	o.net.Audit("firewall_apply", ip, "ufw="+ufw)
	msg := " Раздача интернета в локальную сеть включена, шлюз закрыт от подключений из интернета."

	msg += o.applyDNS(ip)

	state, derr := o.ApplyDHCP(ip)
	if derr != nil {
		return msg + " Автоматическая раздача адресов не включилась: " + ErrText(derr)
	}
	switch state {
	case "":
		return msg
	case "active":
		msg += " Устройства офиса получают адреса автоматически."
	case "waiting_link":
		msg += " Раздача адресов настроена и включится автоматически, как только будет подключён кабель локальной сети."
	default:
		msg += " Раздача адресов настроена, служба ещё не запущена — проверьте подключение кабеля локальной сети."
	}
	return msg + o.applyQos(ip)
}

func (o *Orchestrator) DHCPPlan() keagen.Plan { return o.dhcp.BuildPlan(o.dns.Ready()) }

func (o *Orchestrator) ApplyDHCP(ip string) (string, error) {
	plan := o.DHCPPlan()
	if len(plan.LANs) == 0 {
		return "", nil
	}
	_, state, err := o.dhcp.Apply(plan)
	if err != nil {
		o.net.Audit("dhcp_apply_failed", ip, err.Error())
		return "", err
	}
	o.net.Audit("dhcp_apply", ip, "состояние: "+state)
	return state, nil
}

func (o *Orchestrator) applyQos(ip string) string {
	plan := o.qos.BuildPlan()
	if !plan.Enabled || plan.WAN == "" {
		return ""
	}
	res, err := o.qos.Apply(plan)
	if err != nil {
		o.net.Audit("qos_apply_failed", ip, err.Error())
		return " QoS не перенастроился: " + ErrText(err) + " Откройте страницу «QoS» и примените его заново."
	}
	if res.Changed {
		o.net.Audit("qos_apply", ip, "перенастроен под новую сеть")
		return " QoS перенастроен под новую сеть."
	}
	return ""
}

func (o *Orchestrator) applyDNS(ip string) string {
	plan := o.dns.BuildPlan()
	if len(plan.Segments) == 0 {
		return ""
	}
	res, err := o.dns.Apply(plan)
	if err != nil {
		o.dns.SetReady(false)
		o.net.Audit("dns_apply_failed", ip, err.Error())
		return " Локальное разрешение имён не включилось: " + ErrText(err)
	}
	o.dns.SetReady(res.Verified)
	o.net.Audit("dns_apply", ip, "состояние: "+res.State)
	if res.Verified {
		return " Панель доступна по адресу https://vpn.lan."
	}
	return " Локальное разрешение имён настроено, но пока не отвечает — клиентам продолжат выдаваться публичные серверы."
}
