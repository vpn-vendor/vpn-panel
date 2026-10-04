package dhcp

import (
	"net/netip"
	"time"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
	"github.com/vpn-vendor/vpn-panel-core/internal/change"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/usertext"
)

const MaxReservationLabel = 50

type Section struct {
	Reservations []SectionReservation `json:"reservations" table:"dhcp_reservations"`
}

type SectionReservation struct {
	Label  string `json:"label"`
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Subnet string `json:"subnet"`
}

func ReadSection() (Section, error) {
	var rows []models.DhcpReservation
	if err := facades.Orm().Query().OrderBy("id").Find(&rows); err != nil {
		return Section{}, err
	}
	out := Section{Reservations: []SectionReservation{}}
	for _, r := range rows {
		out.Reservations = append(out.Reservations, SectionReservation{Label: r.Label, MAC: r.MAC, IP: r.IP, Subnet: r.Subnet})
	}
	return out, nil
}

func ValidateSection(v Section, lans []netip.Prefix) fielderr.List {
	var errs fielderr.List
	macs, ips := map[string]bool{}, map[string]bool{}
	for n, r := range v.Reservations {
		path := fielderr.Row("reservations", n, rowKey(r))

		if err := usertext.ValidatePlain(r.Label, MaxReservationLabel); err != nil {
			errs.Add(fielderr.Join(path, "label"), "название: %s", err.Error())
		}
		switch {
		case !keagen.ValidMAC(r.MAC):
			errs.Add(fielderr.Join(path, "mac"), "неверный аппаратный адрес %q (вид a4:bb:6d:1f:22:90)", r.MAC)
		case macs[r.MAC]:
			errs.Add(fielderr.Join(path, "mac"), "для этого устройства адрес уже закреплён")
		}
		macs[r.MAC] = true
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() {
			errs.Add(fielderr.Join(path, "ip"), "неверный адрес %q", r.IP)
			continue
		}
		if ips[r.IP] {
			errs.Add(fielderr.Join(path, "ip"), "этот адрес уже закреплён за другим устройством")
		}
		ips[r.IP] = true
		seg, ok := lanOf(lans, ip)
		if !ok {
			errs.Add(fielderr.Join(path, "ip"), "адрес не принадлежит ни одному сегменту локальной сети")
			continue
		}
		if err := keagen.ValidateReservationIP(seg.String(), r.IP); err != nil {
			errs.Add(fielderr.Join(path, "ip"), "%s", err.Error())
		}
		if r.Subnet != seg.Masked().String() {
			errs.Add(fielderr.Join(path, "subnet"), "подсеть закрепления %q не совпадает с сегментом %s", r.Subnet, seg.Masked())
		}
	}
	return errs
}

func lanOf(lans []netip.Prefix, ip netip.Addr) (netip.Prefix, bool) {
	for _, p := range lans {
		if p.Masked().Contains(ip) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func rowKey(r SectionReservation) string {
	if keagen.ValidMAC(r.MAC) {
		return r.MAC
	}
	return ""
}

func ApplySection(cur, want Section) error {
	added, changed, removed := change.Rows(cur.Reservations, want.Reservations,
		func(r SectionReservation) string { return r.MAC })
	if len(added)+len(changed)+len(removed) == 0 {
		return nil
	}
	now := time.Now()
	return facades.Orm().Transaction(func(tx orm.Query) error {
		for _, r := range removed {
			if _, err := tx.Where("mac", r.MAC).Delete(&models.DhcpReservation{}); err != nil {
				return err
			}
		}
		for _, r := range changed {
			if _, err := tx.Model(&models.DhcpReservation{}).Where("mac", r.MAC).Update(map[string]any{
				"label": r.Label, "ip": r.IP, "subnet": r.Subnet, "updated_at": now}); err != nil {
				return err
			}
		}
		for _, r := range added {
			if err := tx.Create(&models.DhcpReservation{Label: r.Label, MAC: r.MAC, IP: r.IP, Subnet: r.Subnet,
				CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
		return nil
	})
}

func Edit(lans []netip.Prefix, edit func(*Section) error) (Section, error) {
	return change.Apply(change.Section[Section]{Read: ReadSection,
		Validate: func(v Section) fielderr.List { return ValidateSection(v, lans) }, Apply: ApplySection}, edit)
}

func SubnetFor(lans []netip.Prefix, addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if p, ok := lanOf(lans, ip); ok {
		return p.Masked().String()
	}
	return ""
}
