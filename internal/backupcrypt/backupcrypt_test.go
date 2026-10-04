package backupcrypt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const limit = 1 << 20

func TestRoundTrip(t *testing.T) {
	plain := []byte(`{"format":"vpn-panel-settings","sections":{}}`)
	c, err := Encrypt(plain, "верный-пароль-копии")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c, plain) || bytes.Contains(c, []byte("vpn-panel-settings")) {
		t.Fatal("содержимое видно в зашифрованном файле")
	}

	if !bytes.HasPrefix(c, []byte("age-encryption.org/v1\n")) {
		t.Fatalf("заголовок не по спецификации age: %q", c[:30])
	}
	got, err := Decrypt(c, "верный-пароль-копии", limit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("расшифровано другое: %q", got)
	}
}

func TestWrongPasswordRefused(t *testing.T) {
	c, err := Encrypt([]byte("настройки"), "пароль-один-длинный")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(c, "пароль-два-длинный", limit); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("чужой пароль: %v, ждали отказ", err)
	}
}

func TestTamperDetected(t *testing.T) {
	c, err := Encrypt(bytes.Repeat([]byte("x"), 4096), "пароль-копии-длинный")
	if err != nil {
		t.Fatal(err)
	}
	for _, pos := range []int{len(c) - 1, len(c) / 2, len(c) - 100} {
		bad := append([]byte(nil), c...)
		bad[pos] ^= 0x01
		if _, err := Decrypt(bad, "пароль-копии-длинный", limit); err == nil {
			t.Fatalf("изменённый байт %d не обнаружен", pos)
		}
	}
}

func TestSizeLimit(t *testing.T) {
	c, err := Encrypt(bytes.Repeat([]byte("x"), 2048), "пароль-копии-длинный")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(c, "пароль-копии-длинный", 1024); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("потолок размера не сработал: %v", err)
	}
}

func TestOnlyAdapterImportsFormat(t *testing.T) {
	root := "../.."
	found := 0
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() && (e.Name() == ".git" || e.Name() == "node_modules" || e.Name() == "vendor") {
			return filepath.SkipDir
		}
		if e.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(`"filippo.io/age`)) {
			found++
			if !strings.Contains(filepath.ToSlash(p), "internal/backupcrypt/") {
				t.Errorf("%s: пакет формата копии используется мимо адаптера", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("страж не нашёл даже сам адаптер — поиск сломан")
	}
}
