package nftgen

import "github.com/vpn-vendor/vpn-panel-core/internal/hostcaps"

type Caps struct {
	Witness bool

	DHCPWatch bool
}

var Options = []hostcaps.Option[Caps]{
	{ID: "nft.forward_witness", Consumers: []string{"network"}, Enable: func(c *Caps) { c.Witness = true },
		Title: "Счётчики-свидетели пересылки",
		Missing: "Фаервол этой системы не принимает счётчики-свидетели: шлюз не сможет доказать, " +
			"что чужие правила режут интернет офиса. Защита и интернет работают."},
	{ID: "nft.dhcp_watch", Consumers: []string{"network"}, Enable: func(c *Caps) { c.DHCPWatch = true },
		Title: "Наблюдение за чужой раздачей адресов",
		Missing: "Фаервол этой системы не принимает набор наблюдения: шлюз не увидит второй сервер " +
			"раздачи адресов в сети офиса. Защита и интернет работают."},
}

func ProbeRuleset(c Caps) []byte {
	p := ProbePlan()
	out := p.Generate(c)
	if c.DHCPWatch {
		out = append(out, ProbeDHCPWatch().Create(DHCPFresh, DHCPWindow)...)
	}
	return out
}
