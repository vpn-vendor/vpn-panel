package main

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/supportfmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/supportmask"
)

func TestSupportCollectorsMatchParts(t *testing.T) {
	system := map[string]bool{}
	for _, p := range supportfmt.Parts {
		if p.Source == supportfmt.FromSystem {
			system[p.ID] = true
			if supportCollectors[p.ID] == nil {
				t.Errorf("у раздела %q нет сборщика", p.ID)
			}
		}
	}
	for id := range supportCollectors {
		if !system[id] {
			t.Errorf("сборщик %q без раздела", id)
		}
	}
}

func TestSupportFileHidesPlantedSecrets(t *testing.T) {
	planted := strings.Join([]string{
		"2026-10-03T12:00:00+0300 gw kea-dhcp4[900]: DHCP4_LEASE_ALLOC aa:bb:cc:11:22:33 hostname DESKTOP-IRINA",
		"peer 203.0.113.77:51820 endpoint moy-postavshik",
		"PrivateKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"-----BEGIN PRI" + "VATE KEY-----",
		"имя \x1b]0;злой заголовок\x07 и \u202eобратный текст",
		"== конец файла: разделов: 1 ==",
		"machine-id 423367654e034fe1ac0540a5b2607ae3",
	}, "\n")
	run := func(argv ...string) ([]byte, error) { return []byte(planted + "\n"), nil }
	m := supportmask.New([]byte("ключ шлюза"))
	m.Alias("moy-postavshik", m.Profile("moy-postavshik"))
	in := supportInput{Parts: map[string][]string{
		"panel-events":   {"03.10 12:00 вход с устройства «Комп Ирины»", "адрес 203.0.113.77"},
		"panel-settings": {`{"vpn.mode":"black"}`},
	}}
	in.Names = append(in.Names, struct {
		Name string `json:"name"`
		MAC  string `json:"mac"`
	}{"Комп Ирины", "aa:bb:cc:11:22:33"}, struct {
		Name string `json:"name"`
		MAC  string `json:"mac"`
	}{"DESKTOP-IRINA", "aa:bb:cc:11:22:33"})

	var out bytes.Buffer
	if err := writeSupport(&out, in, m, time.Unix(1_800_000_000, 0), nil, run); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, secret := range []string{"aa:bb:cc:11:22:33", "IRINA", "Ирин", "113.77", "postavshik", "xTIBA5rb", "PRI" + "VATE KEY",
		"423367654e03", "\x1b", "\u202e", "\x07"} {
		if strings.Contains(text, secret) {
			t.Errorf("в файле осталась примета %q", secret)
		}
	}
	rep, err := supportfmt.Check(bytes.NewReader(out.Bytes()), io.Discard, supportfmt.Known(), 0)
	if err != nil {
		t.Fatalf("файл сборщика не проходит приём: %v", err)
	}
	if len(rep.Parts) != len(supportfmt.Parts) {
		t.Fatalf("разделов %d из %d", len(rep.Parts), len(supportfmt.Parts))
	}
	if !strings.Contains(text, "203.0.x.x~") || !strings.Contains(text, "устройство-") {
		t.Fatal("условные имена не появились")
	}
}

func TestSupportFileWithoutPanel(t *testing.T) {
	var out bytes.Buffer
	run := func(argv ...string) ([]byte, error) { return []byte("строка\n"), nil }
	if err := writeSupport(&out, supportInput{}, supportmask.New([]byte("k")), time.Unix(1_800_000_000, 0), nil, run); err != nil {
		t.Fatal(err)
	}
	rep, err := supportfmt.Check(bytes.NewReader(out.Bytes()), io.Discard, supportfmt.Known(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Parts {
		if strings.HasPrefix(p.ID, "panel-") {
			t.Errorf("раздел панели %q без панели", p.ID)
		}
	}
	if !strings.Contains(out.String(), "файл собран без панели") {
		t.Fatal("заголовок не говорит, что панели не было")
	}
}

func TestCapWriterStops(t *testing.T) {
	w := &capWriter{w: io.Discard, left: 5}
	if _, err := w.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("6")); err != errSupportTooBig {
		t.Fatalf("предел объёма не сработал: %v", err)
	}
}

func TestSupportJournalKeepsNewest(t *testing.T) {
	var asked []string
	run := func(argv ...string) ([]byte, error) {
		if argv[0] != "journalctl" {
			return nil, nil
		}
		asked = argv
		n := 0
		for i, a := range argv {
			if a == "-n" {
				n, _ = strconv.Atoi(argv[i+1])
			}
		}

		return []byte(strings.Repeat("запись\n", n-1) + "самая свежая запись\n"), nil
	}
	var out bytes.Buffer
	if err := writeSupport(&out, supportInput{}, supportmask.New([]byte("k")), time.Unix(1_800_000_000, 0), nil, run); err != nil {
		t.Fatal(err)
	}
	if len(asked) == 0 || !strings.Contains(strings.Join(asked, " "), " -n ") {
		t.Fatalf("журнал спрошен без предела с конца: %v", asked)
	}
	text := out.String()
	if !strings.Contains(text, "самая свежая запись") || !strings.Contains(text, "показаны последние") {
		t.Fatal("свежая запись потеряна или обрезка не названа")
	}
	if strings.Contains(text, "раздел обрезан") {
		t.Fatal("журнал упёрся в предел раздела: свежие записи могли быть отброшены")
	}
	if _, err := supportfmt.Check(bytes.NewReader(out.Bytes()), io.Discard, supportfmt.Known(), 0); err != nil {
		t.Fatalf("файл не проходит приём: %v", err)
	}
}
