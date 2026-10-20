package controllers

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
	"github.com/vpn-vendor/vpn-panel-core/app/services/dhcp"
)

const dhcpJudgeOwner = "раздел DHCP"

func dhcpPoolCards(stats []dhcp.PoolStat) ui.ItemGrid {
	grid := ui.ItemGrid{Cards: true}
	for _, st := range stats {
		level, word := ui.OK, "адресов хватает"
		if st.Percent >= dhcp.PoolWarnPercent {
			level, word = ui.Warn, fmt.Sprintf("заполнен на %d %%", st.Percent)
		}
		free := st.Size - st.Used
		if free < 0 {
			free = 0
		}
		grid.Items = append(grid.Items, ui.ItemCard{
			Title: st.Name,
			Tags:  []ui.Tag{{Text: word, Judged: ui.Judge(level, dhcpJudgeOwner)}},
			Meta:  []string{st.CIDR, "свободно " + ui.Plural(free, "адрес", "адреса", "адресов")},
			Bar: &ui.UsageBar{Label: "Занято", Value: fmt.Sprint(st.Used), Of: fmt.Sprintf("из %d", st.Size),
				Percent: st.Percent, Judged: ui.Judge(level, dhcpJudgeOwner)},
		})
	}
	return grid
}

type dhcpRow struct {
	Kind     string
	Label    string
	IP       string
	MAC      string
	Until    string
	HasLease bool
	Pinned   bool
	ResID    uint
	Waiting  bool
	Stale    bool
}

func dhcpRows(leases []leaseView, reservations []reservationView) []dhcpRow {
	byMAC := map[string]reservationView{}
	for _, r := range reservations {
		byMAC[r.MAC] = r
	}
	seen := map[string]bool{}
	rows := make([]dhcpRow, 0, len(leases)+len(reservations))
	for _, l := range leases {
		row := dhcpRow{Label: l.Hostname, IP: l.Address, MAC: l.MAC, Until: l.Until, HasLease: true}
		if r, ok := byMAC[l.MAC]; ok && r.IP == l.Address {
			row.Pinned, row.ResID = true, r.ID
			if r.Label != "" {
				row.Label = r.Label
			}
			seen[r.MAC] = true
		}
		rows = append(rows, row)
	}
	for _, r := range reservations {
		if seen[r.MAC] {
			continue
		}
		rows = append(rows, dhcpRow{Label: r.Label, IP: r.IP, MAC: r.MAC, Pinned: true, ResID: r.ID,
			Waiting: r.Waiting, Stale: r.Stale})
	}
	for i := range rows {
		r := &rows[i]
		switch {
		case r.Stale:
			r.Kind = "stale"
		case r.Waiting:
			r.Kind = "waiting"
		case r.Pinned:
			r.Kind = "pinned"
		default:
			r.Kind = "lease"
		}
	}
	return rows
}

func dhcpFilters() ui.FilterBar {
	return ui.FilterBar{ID: "dhcp-rows", Filters: []ui.TimelineFilter{
		{Label: "Все"}, {Kind: "pinned", Label: "Закреплённые"}, {Kind: "lease", Label: "Выданные"}, {Kind: "waiting", Label: "Ожидают"}}}
}
