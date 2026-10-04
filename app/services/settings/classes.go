package settings

type Section string

const (
	SectionNetwork   Section = "network"
	SectionDHCP      Section = "dhcp"
	SectionDNS       Section = "dns"
	SectionQoS       Section = "qos"
	SectionVPN       Section = "vpn"
	SectionSecurity  Section = "security"
	SectionRetention Section = "retention"
	SectionDiag      Section = "diagnostics"
	SectionMetrics   Section = "metrics"
	SectionUpdates   Section = "updates"
	SectionDevices   Section = "devices"
	SectionAuth      Section = "auth"
)

var sectionTitles = map[Section]string{
	SectionNetwork: "Сеть", SectionDHCP: "DHCP", SectionDNS: "DNS", SectionQoS: "QoS",
	SectionVPN: "VPN", SectionSecurity: "Защита", SectionRetention: "Хранение данных",
	SectionDiag: "Диагностика", SectionMetrics: "Сбор показателей", SectionUpdates: "Обновления",
	SectionDevices: "Устройства", SectionAuth: "Вход в панель",
}

func (s Section) Title() string {
	if t, ok := sectionTitles[s]; ok {
		return t
	}
	return string(s)
}

type Data int

const (
	_ Data = iota

	Policy

	Office

	Provider

	Machine

	Secret

	State
)

type Risk int

const (
	_ Risk = iota

	Safe

	Notable

	Dangerous
)

func (d Data) InCopy() bool {
	return d == Policy || d == Office || d == Provider || d == Secret
}

func InTemplate(d Data, r Risk) bool {
	return d == Policy && (r == Safe || r == Notable)
}

func TemplateConsent(d Data, r Risk) bool {
	return InTemplate(d, r) && r == Notable
}
