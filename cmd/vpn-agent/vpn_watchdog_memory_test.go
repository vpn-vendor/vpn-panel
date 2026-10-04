package main

import "testing"

func TestIntentFingerprintDecidesWhatSurvives(t *testing.T) {
	base := vpnPlan{Slug: "ofis", Protocol: "openvpn", Mode: "black", OnFailure: "strict", MTU: 0}
	same := planFingerprint(base)
	if planFingerprint(base) != same {
		t.Fatal("отпечаток обязан быть устойчивым: иначе осторожность теряется на ровном месте")
	}

	for _, other := range []vpnPlan{
		{Slug: "drugoy", Protocol: "openvpn", Mode: "black", OnFailure: "strict"},
		{Slug: "ofis", Protocol: "wireguard", Mode: "black", OnFailure: "strict"},
		{Slug: "ofis", Protocol: "openvpn", Mode: "white", OnFailure: "strict"},
		{Slug: "ofis", Protocol: "openvpn", Mode: "black", OnFailure: "direct"},
		{Slug: "ofis", Protocol: "openvpn", Mode: "black", OnFailure: "strict", MTU: 1400},
	} {
		if planFingerprint(other) == same {
			t.Fatalf("намерение изменилось, а отпечаток тот же: %+v", other)
		}
	}
}

func TestMissingMemoryIsNotConfidence(t *testing.T) {
	got := loadWatchdogMemory(vpnPlan{Slug: "нет-такого-профиля-и-файла", Mode: "black"})
	if got.backoff != 0 || !got.nextTry.IsZero() || got.Degraded {
		t.Fatalf("отсутствие памяти обязано давать пустое состояние: %+v", got)
	}
}

func TestPausedIsVisibleToPathsBesidesWatchdog(t *testing.T) {

	if pausedForPlan(vpnPlan{Slug: "нет-профиля", Mode: "black"}) {
		t.Fatal("без записи попытки не считаются остановленными")
	}
}

func TestRestartKeepsPendingServices(t *testing.T) {
	prev := watchdogState{servicesPending: true, reapplyNotBefore: 12345}
	loaded := watchdogState{backoff: 2 * retryMin, nextTry: 777, reapplyNotBefore: 999}
	got := carryOverOnRestart(prev, loaded)
	if !got.servicesPending {
		t.Fatal("отметка «службы не применены» потеряна при перезапуске сторожа")
	}
	if got.reapplyNotBefore != 0 {
		t.Fatalf("пауза прошлой неудачи перенесена: %v", got.reapplyNotBefore)
	}
	if got.backoff != 2*retryMin || got.nextTry != 777 {
		t.Fatalf("осторожность к серверу потеряна: %+v", got)
	}

	in := watchdogInput{Present: true, HandshakeOK: true, AgeSec: 1, StaleSec: 60,
		ServicesPending: got.servicesPending, ReapplyDue: due(got.reapplyNotBefore)}
	if !whenReapply(in) {
		t.Fatalf("службы не применяются по живому рукопожатию: %+v", in)
	}
}
