package ui

type RoleName struct {
	Initial   string
	Nom       string
	Gen       string
	Dat       string
	Ins       string
	Plural    string
	PluralGen string
	PluralDat string
}

var (
	MainAdmin = RoleName{Initial: "Г", Nom: "Гл. Админ", Gen: "Гл. Админа", Dat: "Гл. Админу", Ins: "Гл. Админом"}

	JuniorAdmin = RoleName{Initial: "М", Nom: "Менеджер", Gen: "Менеджера", Dat: "Менеджеру", Ins: "Менеджером",
		Plural: "Менеджеры", PluralGen: "Менеджеров", PluralDat: "Менеджерам"}
)
