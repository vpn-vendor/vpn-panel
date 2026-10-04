package backupcode

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var form = regexp.MustCompile(`^[` + Alphabet + `]{4}-[` + Alphabet + `]{4}$`)

func TestIssueAndUseOnce(t *testing.T) {
	s := New()
	code, err := s.Issue()
	if err != nil || !form.MatchString(code) {
		t.Fatalf("код %q: %v", code, err)
	}
	if err := s.Use(strings.ToLower(strings.ReplaceAll(code, "-", " "))); err != nil {
		t.Fatalf("верный код, набранный по-человечески, отвергнут: %v", err)
	}
	if err := s.Use(code); !errors.Is(err, ErrNoCode) {
		t.Fatalf("код сработал второй раз: %v", err)
	}
}

func TestWrongCodeBurnsAfterAttempts(t *testing.T) {
	s := New()
	code, _ := s.Issue()
	for i := 1; i < Attempts; i++ {
		if err := s.Use("2222-2222"); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("попытка %d: %v", i, err)
		}
	}
	if err := s.Use("2222-2222"); !errors.Is(err, ErrNoCode) {
		t.Fatalf("последняя ошибка не сожгла код: %v", err)
	}
	if err := s.Use(code); !errors.Is(err, ErrNoCode) {
		t.Fatal("сгоревший код сработал")
	}
}

func TestExpires(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s := &Store{now: func() time.Time { return now }}
	code, _ := s.Issue()
	now = now.Add(TTL)
	if err := s.Use(code); !errors.Is(err, ErrNoCode) {
		t.Fatalf("истёкший код сработал: %v", err)
	}
}

func TestNewCodeReplacesOld(t *testing.T) {
	s := New()
	old, _ := s.Issue()
	fresh, _ := s.Issue()
	if old == fresh {
		t.Skip("совпадение кодов — вероятность 2⁻⁴¹")
	}
	if err := s.Use(old); err == nil {
		t.Fatal("прежний код действует после выдачи нового")
	}
	if err := s.Use(fresh); err != nil {
		t.Fatalf("новый код: %v", err)
	}
}

func TestNothingIssued(t *testing.T) {
	if err := New().Use("ABCD-EFGH"); !errors.Is(err, ErrNoCode) {
		t.Fatalf("без выдачи: %v", err)
	}
}
