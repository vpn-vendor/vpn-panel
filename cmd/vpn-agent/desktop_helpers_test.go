package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestKeepDesktopHelpers(t *testing.T) {
	var calls []string
	busy := 2
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "showauto":
			return []byte("wl-clipboard\n"), nil
		case "manual":
			if busy > 0 {
				busy--
				return nil, errors.New("замок занят")
			}
			return nil, nil
		}
		return nil, errors.New("неожиданная команда")
	}
	slept := 0
	keepDesktopHelpers(run, func(time.Duration) { slept++ })
	if busy != 0 || slept != 2 {
		t.Fatalf("ждали двух повторов после занятого замка: повторов %d", slept)
	}
	last := calls[len(calls)-1]
	if last != "manual wl-clipboard" {
		t.Fatalf("помечать надо только пришедших рекомендацией: %q", last)
	}
}

func TestKeepDesktopHelpersNothingToDo(t *testing.T) {
	n := 0
	keepDesktopHelpers(func(args ...string) ([]byte, error) {
		n++
		return nil, nil
	}, func(time.Duration) { t.Fatal("повтор не нужен") })
	if n != 1 {
		t.Fatalf("пометок нет — одна проверка и выход, было вызовов %d", n)
	}
}
