package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func feed(t *testing.T, input string, closeAfter bool) (fd int, done func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if input != "" {
		if _, err := w.WriteString(input); err != nil {
			t.Fatal(err)
		}
	}
	if closeAfter {
		_ = w.Close()
	}
	return int(r.Fd()), func() { _ = r.Close(); _ = w.Close() }
}

func TestReadSecretKeys(t *testing.T) {
	for _, c := range []struct {
		name, in, want, echo string
	}{
		{"буквы и Enter", "abc\r", "abc", "***"},
		{"перевод строки тоже Enter", "abc\n", "abc", "***"},
		{"Backspace стирает", "ab\x7fc\r", "ac", "**\b \b*"},
		{"Ctrl+H стирает", "ab\x08c\r", "ac", "**\b \b*"},
		{"Backspace в пустом поле ничего не делает", "\x7fa\r", "a", "*"},
		{"Ctrl+U очищает", "xyz\x15ok\r", "ok", "***\b \b\b \b\b \b**"},
		{"стрелки и F1 не идут в пароль", "a\x1b[Ab\x1bOPc\x1b[3~d\r", "abcd", "****"},
		{"пустой ответ — законный", "\r", "", ""},
		{"управляющие символы пропускаются", "a\tb\x01\r", "ab", "**"},
		{"ввод после Enter не читается", "ok\rлишнее", "ok", "**"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fd, done := feed(t, c.in, false)
			defer done()
			var echo strings.Builder
			got, err := readSecret(fd, &echo, time.Second)
			if err != nil {
				t.Fatalf("ошибка: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("пароль %q, ждали %q", got, c.want)
			}
			if got == nil {
				t.Fatal("пустой ответ обязан быть пустой строкой, а не отказом")
			}
			if echo.String() != c.echo {
				t.Fatalf("эхо %q, ждали %q", echo.String(), c.echo)
			}
		})
	}
}

func TestReadSecretLimit(t *testing.T) {
	fd, done := feed(t, strings.Repeat("a", consoleMaxSecret+100)+"\r", false)
	defer done()
	var echo strings.Builder
	got, err := readSecret(fd, &echo, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != consoleMaxSecret {
		t.Fatalf("длина %d, ждали %d", len(got), consoleMaxSecret)
	}
}

func TestReadSecretTimeout(t *testing.T) {
	fd, done := feed(t, "начал набирать", false)
	defer done()
	var echo strings.Builder
	start := time.Now()
	got, err := readSecret(fd, &echo, 100*time.Millisecond)
	if !errors.Is(err, errConsoleTimeout) {
		t.Fatalf("ошибка %v, ждали истечение срока", err)
	}
	if got != nil {
		t.Fatalf("недонабранный пароль вернулся: %q", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("срок ответа не соблюдён")
	}
}

func TestReadSecretClosed(t *testing.T) {
	fd, done := feed(t, "abc", true)
	defer done()
	var echo strings.Builder
	got, err := readSecret(fd, &echo, time.Second)
	if err == nil {
		t.Fatalf("закрытая консоль дала ответ %q", got)
	}
}

func TestPickConsoleFont(t *testing.T) {
	for _, c := range []struct {
		h    int
		want string
	}{
		{480, "Uni2-TerminusBold14.psf.gz"},
		{600, "Uni2-TerminusBold16.psf.gz"},
		{720, "Uni2-TerminusBold20x10.psf.gz"},
		{768, "Uni2-TerminusBold20x10.psf.gz"},
		{800, "Uni2-TerminusBold22x11.psf.gz"},
		{1080, "Uni2-TerminusBold28x14.psf.gz"},
		{2160, "Uni2-TerminusBold32x16.psf.gz"},
		{0, "Uni2-TerminusBold16.psf.gz"},
	} {
		if got := pickConsoleFont(c.h).file; got != c.want {
			t.Fatalf("экран %d: шрифт %s, ждали %s", c.h, got, c.want)
		}
	}
}

func TestWrapText(t *testing.T) {
	for _, c := range []struct {
		in    string
		width int
		want  []string
	}{
		{"Смена пароля диска. Введите текущий пароль", 20, []string{"Смена пароля диска.", "Введите текущий", "пароль"}},
		{"коротко", 20, []string{"коротко"}},
		{"  лишние   пробелы  ", 40, []string{"лишние пробелы"}},
		{"оченьдлинноесловобезпробелов", 10, []string{"оченьдлинн", "оесловобез", "пробелов"}},
		{"", 10, nil},
	} {
		got := wrapText(c.in, c.width)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Fatalf("%q по %d: %q, ждали %q", c.in, c.width, got, c.want)
		}
		for _, line := range got {
			if n := len([]rune(line)); n > c.width {
				t.Fatalf("строка %q длиннее %d знаков (%d)", line, c.width, n)
			}
		}
	}
}
