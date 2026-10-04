package vpndriver

import (
	"testing"
)

func TestMarkIsDeterministic(t *testing.T) {
	if Mark != 51820 {
		t.Fatal("метка обязана совпадать с таблицей маршрутизации штатного сценария (0xca6c)")
	}
}

func TestVoiceFitByTransport(t *testing.T) {
	if !VoiceFit(TransportUDP) || VoiceFit(TransportTCP) || !VoiceFit("") {
		t.Fatal("пригодность к телефонии по транспорту")
	}
}

func TestTunnelMTUBounds(t *testing.T) {
	if got := TunnelMTU(1500, 52); got != 1448 {
		t.Fatalf("оверхед 52: %d", got)
	}
	if got := TunnelMTU(1200, 60); got != MinMTU {
		t.Fatalf("ниже минимума нельзя: %d", got)
	}
	if got := TunnelMTU(9000, 60); got != MaxMTU {
		t.Fatalf("выше Ethernet не бывает: %d", got)
	}
}

func TestSlugIsSafeForPathsAndArgv(t *testing.T) {
	for in, want := range map[string]string{
		"Основное":         "osnovnoe",
		"Россия СПб":       "rossiya-spb",
		"../../etc/passwd": "etc-passwd",
		"   ":              "profil",
		"Очень длинное название подключения": "ochen-dlinnoe-nazvanie-p",
	} {
		if got := Slug(in); got != want || !ValidSlug(got) {
			t.Errorf("%q → %q (ожидалось %q)", in, got, want)
		}
	}
	for _, bad := range []string{"", "-a", "A", "a/b", "a b", "aaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if ValidSlug(bad) {
			t.Errorf("слаг %q принят", bad)
		}
	}
}

func TestTruthZeroValueIsUnknown(t *testing.T) {
	var zero Truth
	if zero != Unknown || zero.Known() {
		t.Fatalf("нулевое значение обязано быть Unknown: %v", zero)
	}
	if TruthOf(false) != No || TruthOf(true) != Yes {
		t.Fatal("выполненная проба даёт точный ответ, не Unknown")
	}

	var got Truth
	if err := got.UnmarshalText([]byte("")); err != nil || got != Unknown {
		t.Fatalf("пустое значение обязано стать Unknown без ошибки: %v %v", got, err)
	}
	for s, want := range map[string]Truth{"yes": Yes, "no": No, "мусор": Unknown} {
		var v Truth
		_ = v.UnmarshalText([]byte(s))
		if v != want {
			t.Fatalf("%q -> %v, ждали %v", s, v, want)
		}
	}
}
