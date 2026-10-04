package usertext

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	if got, err := Validate("  ПК   Ирины\u200b ", 40, ""); err != nil || got != "ПК Ирины" {
		t.Fatalf("очистка: %q %v", got, err)
	}
	for _, bad := range []string{"<b>", "a\"b", "rm;x"} {
		if _, err := Validate(bad, 40, ""); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
	if _, err := Validate("DESKTOP_1", 40, ""); err == nil {
		t.Error("подчёркивание без разрешения поля принято")
	}
	if _, err := Validate("DESKTOP_1", 40, "_"); err != nil {
		t.Errorf("подчёркивание с разрешением поля: %v", err)
	}
	if _, err := Validate("абвгд", 4, ""); err == nil {
		t.Error("предел длины не действует")
	}
}

func TestValidatePlain(t *testing.T) {
	if err := ValidatePlain("Офис #2 (резерв)", 60); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "   ", "a\nb", "a\u200bb", strings.Repeat("я", 61)} {
		if ValidatePlain(bad, 60) == nil {
			t.Errorf("%q принят", bad)
		}
	}
}
