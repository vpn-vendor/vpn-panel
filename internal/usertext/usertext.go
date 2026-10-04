package usertext

import (
	"errors"
	"strings"
	"unicode"
)

const Punct = "-.,()«»№/"

func Validate(raw string, max int, extra string) (string, error) {
	var b strings.Builder
	for _, r := range raw {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == ' ':
			b.WriteRune(r)
		case strings.ContainsRune(Punct+extra, r):
			b.WriteRune(r)
		default:
			return "", errors.New("можно использовать только буквы, цифры, пробел и знаки " + spaced(Punct+extra))
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len([]rune(out)) > max {
		return "", errors.New("слишком длинный текст")
	}
	return out, nil
}

func spaced(s string) string {
	parts := make([]string, 0, len(s))
	for _, r := range s {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, " ")
}

func ValidatePlain(raw string, max int) error {
	for _, r := range raw {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return errors.New("в тексте есть управляющие или невидимые символы")
		}
	}
	switch n := len([]rune(strings.TrimSpace(raw))); {
	case n == 0:
		return errors.New("текст не может быть пустым")
	case n > max:
		return errors.New("слишком длинный текст")
	}
	return nil
}
