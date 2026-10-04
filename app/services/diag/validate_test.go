package diag

import "testing"

func TestValidateTextAllowlist(t *testing.T) {
	ok := map[string]string{
		"  Ирина,  бухгалтерия (правый угол) ": "Ирина, бухгалтерия (правый угол)",
		"Office-PC №7 / Иван":                  "Office-PC №7 / Иван",

		"Каб\u200b.\x01 12": "Каб. 12",
	}
	for in, want := range ok {
		got, err := ValidateText(in, MaxLocation)
		if err != nil || got != want {
			t.Fatalf("%q → %q (%v), want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"<script>alert(1)</script>", "x' OR 1=1 --", "Ирина;", "a\"b", "тест{}", "http://x"} {
		if _, err := ValidateText(bad, MaxLabel); err == nil {
			t.Fatalf("%q обязан отклоняться", bad)
		}
	}
	if _, err := ValidateText("оченьдлинноеназваниеоченьдлинноеназваниеоченьдлинноеназвание", MaxLabel); err == nil {
		t.Fatal("длина")
	}
}
