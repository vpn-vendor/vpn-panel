package dhcp

import (
	"net/netip"
	"testing"
)

var lans = []netip.Prefix{netip.MustParsePrefix("192.168.11.1/24")}

func goodDHCP() Section {
	return Section{Reservations: []SectionReservation{
		{Label: "Принтер бухгалтерии", MAC: "02:00:00:00:10:01", IP: "192.168.11.50", Subnet: "192.168.11.0/24"},
		{Label: "Принтер #2 (Ирины)", MAC: "02:00:00:00:10:02", IP: "192.168.11.51", Subnet: "192.168.11.0/24"},
	}}
}

func TestValidateSection(t *testing.T) {
	if errs := ValidateSection(goodDHCP(), lans); len(errs) > 0 {
		t.Fatalf("годный раздел отвергнут: %v", errs.Err())
	}
	other := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	if !ValidateSection(goodDHCP(), other).Has("reservations[02:00:00:00:10:01].ip") {
		t.Error("закрепление вне подсети желаемого состояния принято")
	}
	for _, c := range []struct {
		name string
		edit func(*Section)
		path string
	}{
		{"пустое название", func(s *Section) { s.Reservations[0].Label = " " }, "reservations[02:00:00:00:10:01].label"},
		{"название с переводом строки", func(s *Section) { s.Reservations[0].Label = "x\ny" }, "reservations[02:00:00:00:10:01].label"},
		{"MAC не в каноне", func(s *Section) { s.Reservations[0].MAC = "02:00:00:00:10:0G" }, "reservations[0].mac"},
		{"MAC дважды", func(s *Section) { s.Reservations[1].MAC = s.Reservations[0].MAC }, "reservations[02:00:00:00:10:01].mac"},
		{"адрес дважды", func(s *Section) { s.Reservations[1].IP = s.Reservations[0].IP }, "reservations[02:00:00:00:10:02].ip"},
		{"адрес шлюза", func(s *Section) { s.Reservations[0].IP = "192.168.11.1" }, "reservations[02:00:00:00:10:01].ip"},
		{"адрес в пуле", func(s *Section) { s.Reservations[0].IP = "192.168.11.150" }, "reservations[02:00:00:00:10:01].ip"},
		{"не адрес", func(s *Section) { s.Reservations[0].IP = "192.168.11" }, "reservations[02:00:00:00:10:01].ip"},
		{"подсеть не та", func(s *Section) { s.Reservations[0].Subnet = "192.168.0.0/16" }, "reservations[02:00:00:00:10:01].subnet"},
	} {
		v := goodDHCP()
		c.edit(&v)
		if !ValidateSection(v, lans).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateSection(v, lans).Err())
		}
	}
}

func TestRowPathSurvivesRemoval(t *testing.T) {
	v := goodDHCP()
	v.Reservations[1].Label = "x\ny"
	before := ValidateSection(v, lans)
	v.Reservations = v.Reservations[1:]
	if added := ValidateSection(v, lans).Beyond(before); len(added) > 0 {
		t.Fatalf("удаление соседней строки дало «новые» ошибки: %v", added.Err())
	}
}

func TestSubnetFor(t *testing.T) {
	if SubnetFor(lans, "192.168.11.50") != "192.168.11.0/24" || SubnetFor(lans, "10.0.0.5") != "" {
		t.Fatal("подсеть закрепления")
	}
}
