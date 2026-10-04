package nftgen

import "strings"

func (p *FirewallPlan) Lockdown() []byte {
	if len(p.LANs) == 0 {
		return nil
	}
	lanNames := make([]string, 0, len(p.LANs))
	for _, l := range p.LANs {
		lanNames = append(lanNames, l.Name)
	}
	lanSet := quotedSet(lanNames)

	var b strings.Builder
	b.WriteString("table inet vpn_panel\n")
	b.WriteString("delete table inet vpn_panel\n")
	b.WriteString("table inet vpn_panel {\n")

	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy drop;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\tiifname " + lanSet + " accept\n")
	if len(p.WANs) > 0 {
		b.WriteString("\t\tiifname " + quotedSet(p.WANs) + " udp sport 67 udp dport 68 accept\n")
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy drop;\n")
	b.WriteString("\t}\n")

	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy drop;\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	b.WriteString("\t\toifname " + lanSet + " accept\n")
	if len(p.WANs) > 0 {
		b.WriteString("\t\toifname " + quotedSet(p.WANs) + " udp sport 68 udp dport 67 accept\n")
	}
	b.WriteString("\t}\n")

	b.WriteString("}\n")
	return []byte(b.String())
}
