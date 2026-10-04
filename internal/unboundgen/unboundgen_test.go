package unboundgen

import (
	"strings"
	"testing"
)

func known() map[string]bool { return map[string]bool{"ens4": true, "ens5": true} }

func TestGenerateExplicitAddressesOnly(t *testing.T) {
	p := Plan{Segments: []Segment{
		{Name: "ens5", CIDR: "10.10.0.1/24"},
		{Name: "ens4", CIDR: "192.168.88.1/24"},
	}}
	if err := p.Validate(known()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate())

	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "interface:") && strings.Contains(line, "0.0.0.0") {
			t.Fatalf("запрещённая привязка ко всем адресам: %q", line)
		}
	}
	for _, want := range []string{
		"interface: 127.0.0.1",
		"interface: 192.168.88.1",
		"interface: 10.10.0.1",
		"access-control: 0.0.0.0/0 refuse",
		"access-control: 127.0.0.0/8 allow",
		"access-control: 192.168.88.0/24 allow",
		"access-control: 10.10.0.0/24 allow",
		`local-zone: "vpn.lan." static`,
		`local-data: "vpn.lan. IN A 192.168.88.1"`,
		"forward-addr: 9.9.9.9",
		"ip-freebind: yes",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("конфигурация не содержит %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, "resolv.conf") {
		t.Fatal("пересылка через resolv.conf запрещена — это петля")
	}
}

func TestUpstreamsKeepBeingProbedAfterOutage(t *testing.T) {
	for _, p := range []Plan{
		{Segments: []Segment{{Name: "ens4", CIDR: "192.168.88.1/24"}}},
		{Segments: []Segment{{Name: "ens4", CIDR: "192.168.88.1/24"}}, OutgoingAddress: "10.66.66.2"},
	} {
		if !strings.Contains(string(p.Generate()), "infra-keep-probing: yes") {
			t.Fatalf("резолвер перестанет пробовать вышестоящие серверы после обрыва:\n%s", p.Generate())
		}
	}
}

func TestDeterministic(t *testing.T) {
	a := Plan{Segments: []Segment{{Name: "ens4", CIDR: "192.168.88.1/24"}, {Name: "ens5", CIDR: "10.10.0.1/24"}}}
	b := Plan{Segments: []Segment{a.Segments[1], a.Segments[0]}}
	if string(a.Generate()) != string(b.Generate()) {
		t.Fatal("порядок сегментов не должен влиять на результат")
	}
}

func TestListenAddresses(t *testing.T) {
	p := Plan{Segments: []Segment{{Name: "ens4", CIDR: "192.168.88.1/24"}}}
	got := p.ListenAddresses()
	if len(got) != 2 || got[0] != "127.0.0.1" || got[1] != "192.168.88.1" {
		t.Fatalf("got %v", got)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Plan{
		"empty":       {},
		"unknown nic": {Segments: []Segment{{Name: "eth9", CIDR: "192.168.1.1/24"}}},
		"bad name":    {Segments: []Segment{{Name: "a b", CIDR: "192.168.1.1/24"}}},
		"bad cidr":    {Segments: []Segment{{Name: "ens4", CIDR: "мусор"}}},
		"unspecified": {Segments: []Segment{{Name: "ens4", CIDR: "0.0.0.0/0"}}},
		"dup":         {Segments: []Segment{{Name: "ens4", CIDR: "192.168.1.1/24"}, {Name: "ens4", CIDR: "10.0.0.1/24"}}},
	}
	for name, p := range cases {
		if err := p.Validate(known()); err == nil {
			t.Fatalf("%s: ожидалась ошибка", name)
		}
	}
}

func TestOutgoingInterfacePinnedToTunnel(t *testing.T) {
	p := Plan{
		Segments:        []Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}},
		OutgoingAddress: "10.66.66.2",
	}
	if err := p.Validate(map[string]bool{"ens4": true}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate())
	if !strings.Contains(out, "outgoing-interface: 10.66.66.2") {
		t.Fatalf("нет привязки к каналу:\n%s", out)
	}
	if !strings.Contains(out, "do-ip6: no") {
		t.Fatalf("канал утечки через адреса нового поколения обязан быть закрыт:\n%s", out)
	}

	if !strings.Contains(out, `local-data: "vpn.lan. IN A 192.168.11.1"`) {
		t.Fatalf("локальное имя панели пропало:\n%s", out)
	}
}

func TestWhiteModeHasNoOutgoingPin(t *testing.T) {
	p := Plan{Segments: []Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}}}
	out := string(p.Generate())
	if strings.Contains(out, "outgoing-interface") || strings.Contains(out, "do-ip6") {
		t.Fatalf("в белом режиме привязки быть не должно:\n%s", out)
	}
}

func TestCustomForwarders(t *testing.T) {
	p := Plan{
		Segments:   []Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}},
		Forwarders: []string{"10.66.66.1"},
	}
	if err := p.Validate(map[string]bool{"ens4": true}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out := string(p.Generate())
	if !strings.Contains(out, "forward-addr: 10.66.66.1") {
		t.Fatalf("выбранный администратором сервер не применён:\n%s", out)
	}
	for _, def := range Upstream {
		if strings.Contains(out, "forward-addr: "+def) {
			t.Fatalf("сервер по умолчанию обязан быть заменён, а не дополнен:\n%s", out)
		}
	}
}

func TestBadOutgoingAndForwardersRejected(t *testing.T) {
	base := []Segment{{Name: "ens4", CIDR: "192.168.11.1/24"}}
	known := map[string]bool{"ens4": true}
	cases := []Plan{
		{Segments: base, OutgoingAddress: "не-адрес"},
		{Segments: base, OutgoingAddress: "0.0.0.0"},
		{Segments: base, Forwarders: []string{"8.8.8.8", "мусор"}},
	}
	for i, p := range cases {
		if err := p.Validate(known); err == nil {
			t.Errorf("случай %d: ожидался отказ", i)
		}
	}
}
