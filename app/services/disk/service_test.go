package disk

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
)

func TestCipherTextHasNoRawNames(t *testing.T) {
	cases := map[string]diskcrypt.Status{
		"AES-256, с ускорением процессора":                                          {Cipher: "aes-xts-plain64", KeyBits: 512},
		"Adiantum-256 — у процессора нет ускорения AES, этот шифр для него быстрее": {Cipher: "xchacha12,aes-adiantum-plain64", KeyBits: 256},
		"шифр, выбранный при установке":                                             {Cipher: "serpent-xts-plain64", KeyBits: 512},
	}
	for want, st := range cases {
		if got := CipherText(st); got != want {
			t.Fatalf("%s: %q, ждали %q", st.Cipher, got, want)
		}
	}
}

func TestLastChangeText(t *testing.T) {
	if text, warn := LastChangeText(diskcrypt.Status{LastChange: "gave_up"}); text == "" || !warn {
		t.Fatal("три неверных текущих пароля — повод для внимания")
	}
	if text, _ := LastChangeText(diskcrypt.Status{}); text != "" {
		t.Fatal("без смен — без строки")
	}
}
