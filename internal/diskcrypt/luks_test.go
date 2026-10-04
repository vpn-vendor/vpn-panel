package diskcrypt

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

func TestParseSlots(t *testing.T) {
	dump := []byte(`{"keyslots":{"2":{"type":"luks2"},"0":{"type":"luks2"}},"tokens":{},"segments":{},"digests":{},"config":{}}`)
	got, err := ParseSlots(dump)
	if err != nil || len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("ParseSlots = %v, %v", got, err)
	}
	if _, err := ParseSlots([]byte(`{"keyslots":{"x":{}}}`)); err == nil {
		t.Fatal("нечисловой слот обязан быть ошибкой")
	}
}

func TestParseUnlockedSlot(t *testing.T) {
	out := "Keyslot 1 candidate for unlock.\nKey slot 1 unlocked.\nCommand successful.\n"
	if got := ParseUnlockedSlot(out); got != 1 {
		t.Fatalf("слот %d, нужен 1", got)
	}
	if got := ParseUnlockedSlot("No key available with this passphrase.\n"); got != -1 {
		t.Fatalf("неверный ключ: слот %d, нужно -1", got)
	}
}

func TestParseStatusDevice(t *testing.T) {
	out := "/dev/mapper/system is active and is in use.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n  device:  /dev/vda3\n  sector size:  512\n"
	if got := ParseStatusDevice(out); got != "/dev/vda3" {
		t.Fatalf("устройство %q", got)
	}
}

func TestTextKnownAndUnknown(t *testing.T) {
	if got := Text(string(PromptNew)); got != "Придумайте пароль диска" {
		t.Fatalf("текст vp:new: %q", got)
	}
	if got := Text("vp:nope"); got != "vp:nope" {
		t.Fatalf("неизвестный код: %q", got)
	}
}

func TestEveryCodeHasText(t *testing.T) {
	codes := []string{string(PromptNew), string(PromptRepeat), string(MsgIntro), string(MsgMismatch), string(MsgDone), string(MsgFailed)}
	for _, r := range []diskpass.Reason{diskpass.NotLatin, diskpass.Short, diskpass.Trivial, diskpass.Common, diskpass.Context} {
		codes = append(codes, string(ReasonMessage(r)))
	}
	for _, c := range codes {
		if Text(c) == c {
			t.Errorf("у кода %s нет текста", c)
		}
	}
}

const dumpAdiantum = `{"keyslots":{"1":{"type":"luks2","key_size":32,
"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
"kdf":{"type":"argon2id","time":7,"memory":1048576,"cpus":2,"salt":"AA=="}}},
"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0",
"encryption":"xchacha12,aes-adiantum-plain64","sector_size":4096}},
"config":{"json_size":"12288","keyslots_size":"16744448","flags":["allow-discards"]}}`

func TestParseHeaderDataCipherNotSlotCipher(t *testing.T) {
	h, err := ParseHeader([]byte(dumpAdiantum))
	if err != nil {
		t.Fatal(err)
	}
	if h.Cipher != "xchacha12,aes-adiantum-plain64" || h.KeyBits != 256 || h.Slots != 1 || !h.Discards {
		t.Fatalf("заголовок разобран неверно: %+v", h)
	}
	noTrim := strings.Replace(dumpAdiantum, `"flags":["allow-discards"]`, `"flags":[]`, 1)
	if h, _ := ParseHeader([]byte(noTrim)); h.Discards {
		t.Fatal("без флага TRIM не включён")
	}
}

func TestSlotKDF(t *testing.T) {
	k, err := SlotKDF([]byte(dumpAdiantum), 1)
	if err != nil || k.Time != 7 || k.Memory != 1048576 || k.CPUs != 2 {
		t.Fatalf("цена попытки слота: %+v %v", k, err)
	}
	if _, err := SlotKDF([]byte(dumpAdiantum), 0); err == nil {
		t.Fatal("несуществующий слот должен давать ошибку")
	}
	pbkdf2 := strings.Replace(dumpAdiantum, `"type":"argon2id"`, `"type":"pbkdf2"`, 1)
	if _, err := SlotKDF([]byte(pbkdf2), 1); err == nil {
		t.Fatal("слот не argon2id не годится образцом")
	}
}

func TestParseCryptName(t *testing.T) {
	out := "ubuntu--vg-ubuntu--lv lvm\nsystem crypt\nvda3 part\nvda disk\n"
	if got := ParseCryptName(out); got != "system" {
		t.Fatalf("том шифрования: %q", got)
	}
	if got := ParseCryptName("vda2 part\nvda disk\n"); got != "" {
		t.Fatalf("без шифрования имя пустое, а %q", got)
	}
}

func TestInitramfsLayout(t *testing.T) {
	cases := map[string]string{
		"XKBMODEL=\"pc105\"\nXKBLAYOUT=\"us\"\n":  "us",
		"XKBLAYOUT=\"ru,us\"\nXKBVARIANT=\",\"\n": "ru",
		"XKBLAYOUT=\"de\"\n":                      "de",
		"":                                        "",
	}
	for in, want := range cases {
		if got := InitramfsLayout(in); got != want {
			t.Fatalf("%q: %q, ждали %q", in, got, want)
		}
	}
}

func TestInitramfsHasKeymap(t *testing.T) {
	withKmap := "-rw-r--r--   1 root root 1234 Sep 24 12:00 etc/console-setup/cached_UTF-8_del.kmap\n" +
		"-rwxr-xr-x   1 root root  321 Sep 24 12:00 bin/setupcon\n"
	if !InitramfsHasKeymap(withKmap) {
		t.Fatal("раскладка console-setup не найдена")
	}
	if !InitramfsHasKeymap("-rw-r--r-- 1 root root 9 Sep 24 12:00 usr/share/keymaps/i386/qwertz/de.map.gz\n") {
		t.Fatal("раскладка kbd не найдена")
	}
	clean := "-rw-r--r-- 1 root root 9 Sep 24 12:00 usr/lib/systemd/systemd-cryptsetup\n" +
		"-rw-r--r-- 1 root root 9 Sep 24 12:00 usr/share/plymouth/themes/vpn-panel/text-unlock-m.png\n"
	if InitramfsHasKeymap(clean) {
		t.Fatal("без раскладки — ложное срабатывание")
	}
}
