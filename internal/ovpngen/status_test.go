package ovpngen

import (
	"strconv"
	"testing"
)

func feed(t *Tracker, lines ...string) {
	for _, l := range lines {
		t.Feed(l)
	}
}

func TestTrackerClassifiesByStateSequence(t *testing.T) {

	var tr Tracker
	feed(&tr, "1788972212,CONNECTING,,,,,,", "1788972212,WAIT,,,,,,", "1788972212,AUTH,,,,,,", "END",
		">LOG:1788972212,,AUTH: Received control message: AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)",
		">STATE:1788972213,GET_CONFIG,,,,,,", ">STATE:1788972213,EXITING,exit-with-notification,,,,,")
	if got := tr.Failure(1788972214); got != FailAfterTLS {
		t.Fatalf("отказ после TLS: %q", got)
	}
	if tr.ServerMessage != "Data channel cipher negotiation failed (no shared cipher)" || tr.FailCount != 1 {
		t.Fatalf("сообщение сервера/счётчик: %q %d", tr.ServerMessage, tr.FailCount)
	}

	tr = Tracker{}
	feed(&tr, ">STATE:1788971998,WAIT,,,,,,", ">STATE:1788971998,AUTH,,,,,,", ">STATE:1788971998,RECONNECTING,tls-error,,,,,")
	if got := tr.Failure(1788972000); got != FailTLSVerify {
		t.Fatalf("проверка сертификата: %q", got)
	}
	feed(&tr, ">STATE:1788972000,WAIT,,,,,,", ">STATE:1788972000,AUTH,,,,,,", ">STATE:1788972000,RECONNECTING,tls-error,,,,,")
	if tr.FailCount != 2 {
		t.Fatalf("отказы считаются: %d", tr.FailCount)
	}

	tr = Tracker{}
	feed(&tr, ">STATE:1788972074,WAIT,,,,,,")
	if got := tr.Failure(1788972080); got != FailNone {
		t.Fatalf("первые секунды ожидания — ещё не отказ: %q", got)
	}
	if got := tr.Failure(1788972074 + AuthStuckAfterSec); got != FailServerSilent {
		t.Fatalf("долгое ожидание — сервер молчит: %q", got)
	}
	feed(&tr, ">STATE:1788972134,RECONNECTING,tls-error,,,,,")
	if got := tr.Failure(1788972135); got != FailServerSilent {
		t.Fatalf("таймаут рукопожатия без ответа сервера: %q", got)
	}

	tr = Tracker{}
	feed(&tr, ">STATE:1788964151,WAIT,,,,,,", ">STATE:1788964151,AUTH,,,,,,")
	if got := tr.Failure(1788964151 + 10); got != FailNone {
		t.Fatalf("рукопожатие ещё идёт: %q", got)
	}
	if got := tr.Failure(1788964151 + AuthStuckAfterSec); got != FailCertRejected {
		t.Fatalf("сервер не принимает наш сертификат: %q", got)
	}

	tr = Tracker{}
	feed(&tr, ">STATE:1,WAIT,,,,,,", ">STATE:1,AUTH,,,,,,", ">STATE:1,RECONNECTING,tls-error,,,,,")
	tr.Reset()
	if tr.FailCount != 1 || tr.ReachedAuth {
		t.Fatalf("сброс процесса: %+v", tr)
	}
	feed(&tr, ">STATE:70,CONNECTED,SUCCESS,10.8.0.3,192.0.2.10,1194,,")
	if tr.Failure(71) != FailNone || tr.FailCount != 0 || !tr.Last.Connected || tr.Last.LocalIPv4 != "10.8.0.3" {
		t.Fatalf("после подключения: %+v", tr)
	}
}

func TestVerdictSurvivesProcessRestarts(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"нет общего шифра", []string{
			">STATE:100,CONNECTING,,,,,,", ">STATE:100,AUTH,,,,,,",
			">STATE:101,GET_CONFIG,,,,,,", ">STATE:101,EXITING,exit-with-notification,,,,,",
		}, FailAfterTLS},
		{"чужой удостоверяющий центр", []string{
			">STATE:100,WAIT,,,,,,", ">STATE:100,AUTH,,,,,,",
			">STATE:101,RECONNECTING,tls-error,,,,,",
		}, FailTLSVerify},
		{"сервер молчит", []string{
			">STATE:100,WAIT,,,,,,", ">STATE:101,RECONNECTING,tls-error,,,,,",
		}, FailServerSilent},
	}
	for _, c := range cases {
		var tr Tracker
		feed(&tr, c.lines...)
		if got := tr.Failure(102); got != c.want {
			t.Fatalf("%s: живой процесс дал %q, ждали %q", c.name, got, c.want)
		}

		tr.Reset()
		feed(&tr, ">STATE:103,CONNECTING,,,,,,")
		if got := tr.Failure(104); got != c.want {
			t.Fatalf("%s: после перезапуска приговор потерян: %q", c.name, got)
		}

		want := 1
		if c.want == FailServerSilent {
			want = 0
		}
		if tr.FailCount != want {
			t.Fatalf("%s: счётчик попыток: %d, ожидалось %d", c.name, tr.FailCount, want)
		}

		feed(&tr, ">STATE:105,CONNECTED,SUCCESS,10.8.0.3,192.0.2.10,1194,,")
		if got := tr.Failure(106); got != FailNone {
			t.Fatalf("%s: после успеха всё ещё отказ: %q", c.name, got)
		}
	}
}

func TestSilentServerIsNamedDespiteRetryLoop(t *testing.T) {
	var tr Tracker
	for sec := int64(0); sec < 90; sec += 5 {
		feed(&tr,
			">STATE:"+itoa(1000+sec)+",CONNECTING,,,,,,",
			">STATE:"+itoa(1000+sec)+",WAIT,,,,,,")
	}
	if got := tr.Failure(1090); got != FailServerSilent {
		t.Fatalf("девяносто секунд без ответа сервера: %q", got)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestAuthDwellSeparatesCertificateFailures(t *testing.T) {

	var quick Tracker
	feed(&quick, ">STATE:1789031254,WAIT,,,,,,", ">STATE:1789031254,AUTH,,,,,,",
		">STATE:1789031254,RECONNECTING,tls-error,,,,,")
	if got := quick.Failure(1789031255); got != FailTLSVerify {
		t.Fatalf("мгновенный отказ — это проверка сертификата сервера: %q", got)
	}

	var stalled Tracker
	feed(&stalled, ">STATE:1789031254,WAIT,,,,,,", ">STATE:1789031254,AUTH,,,,,,",
		">STATE:1789031314,RECONNECTING,tls-error,,,,,")
	if got := stalled.Failure(1789031315); got != FailCertRejected {
		t.Fatalf("зависшее рукопожатие — сервер не принял наш сертификат: %q", got)
	}

	stalled.Reset()
	feed(&stalled, ">STATE:1789031316,CONNECTING,,,,,,")
	if got := stalled.Failure(1789031317); got != FailCertRejected {
		t.Fatalf("после перезапуска: %q", got)
	}
}

func TestAuthDwellCountsEachHandshakeRound(t *testing.T) {
	var tr Tracker
	for sec := int64(0); sec < 45; sec += 3 {
		feed(&tr,
			">STATE:"+itoa(1789032444+sec)+",WAIT,,,,,,",
			">STATE:"+itoa(1789032444+sec)+",AUTH,,,,,,",
			">STATE:"+itoa(1789032444+sec)+",RECONNECTING,tls-error,,,,,")
	}
	if got := tr.Failure(1789032490); got != FailTLSVerify {
		t.Fatalf("пятнадцать мгновенных кругов — это проверка сертификата сервера, а не %q", got)
	}
}

func TestOnlyServerSeenFailuresCount(t *testing.T) {
	var tr Tracker

	feed(&tr, ">STATE:1,WAIT,,,,,,", ">STATE:61,RECONNECTING,tls-error,,,,,",
		">STATE:63,WAIT,,,,,,", ">STATE:123,RECONNECTING,tls-error,,,,,")
	if tr.FailCount != 0 {
		t.Fatalf("молчание сервера истратило бюджет: %d", tr.FailCount)
	}

	tr = Tracker{}
	feed(&tr, ">STATE:1,WAIT,,,,,,", ">STATE:1,AUTH,,,,,,", ">STATE:2,CONNECTED,SUCCESS,10.8.0.3,192.0.2.10,1194,,",
		">STATE:500,RECONNECTING,ping-restart,,,,,")
	if tr.FailCount != 0 {
		t.Fatalf("обрыв после подключения истратил бюджет: %d", tr.FailCount)
	}

	feed(&tr, ">STATE:502,WAIT,,,,,,", ">STATE:562,RECONNECTING,tls-error,,,,,")
	if tr.FailCount != 0 {
		t.Fatalf("отметки прошлой попытки заразили следующую: %d", tr.FailCount)
	}

	feed(&tr, ">STATE:564,WAIT,,,,,,", ">STATE:564,AUTH,,,,,,", ">STATE:565,RECONNECTING,tls-error,,,,,",
		">STATE:567,WAIT,,,,,,", ">STATE:567,AUTH,,,,,,", ">STATE:568,RECONNECTING,tls-error,,,,,")
	if tr.FailCount != 2 {
		t.Fatalf("отвергнутые проверки не посчитаны: %d", tr.FailCount)
	}
}
