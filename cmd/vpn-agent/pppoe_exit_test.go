package main

import (
	"strings"
	"testing"
)

func TestPPPoEFailureText(t *testing.T) {

	for _, code := range []int{pppdAuthUsRejected, pppdAuthPeerRejected, pppdNegotiationFail} {
		text, final := pppoeFailureText(code)
		if !final {
			t.Fatalf("код %d обязан быть окончательным", code)
		}
		if text == "" {
			t.Fatalf("код %d без объяснения", code)
		}
	}

	for _, code := range []int{pppdConnectFail, pppdEchoTimeout} {
		text, final := pppoeFailureText(code)
		if final {
			t.Fatalf("код %d не может быть окончательным: провайдер может ответить позже", code)
		}
		if text == "" {
			t.Fatalf("код %d без объяснения", code)
		}
	}

	for _, code := range []int{0, 1, 42, 255} {
		if text, _ := pppoeFailureText(code); text != "" {
			t.Fatalf("на код %d выдумано объяснение: %s", code, text)
		}
	}

	for _, code := range []int{pppdAuthUsRejected, pppdAuthPeerRejected,
		pppdNegotiationFail, pppdConnectFail, pppdEchoTimeout} {
		text, _ := pppoeFailureText(code)
		for _, forbidden := range []string{"pppd", "PPPoE", "exit", "code", "systemd", "/etc/"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("в тексте кода %d сырая техническая строка %q: %s", code, forbidden, text)
			}
		}
		if !strings.HasSuffix(strings.TrimSpace(text), ".") {
			t.Fatalf("текст кода %d не похож на законченную фразу: %s", code, text)
		}
	}
}

func TestOnlyAuthFailureBlamesCredentials(t *testing.T) {
	for _, code := range []int{pppdConnectFail, pppdEchoTimeout, pppdAuthPeerRejected, pppdNegotiationFail} {
		text, _ := pppoeFailureText(code)
		if strings.Contains(text, "пароль") && code != pppdAuthUsRejected {
			t.Fatalf("код %d зря обвиняет пароль: %s", code, text)
		}
	}
	if text, _ := pppoeFailureText(pppdAuthUsRejected); !strings.Contains(text, "пароль") {
		t.Fatalf("отказ аутентификации обязан назвать пароль: %s", text)
	}
}
