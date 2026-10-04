package main

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

func TestWatchdogDecisionTable(t *testing.T) {
	cases := []struct {
		name string
		in   watchdogInput
		want string
	}{
		{"канал жив — ничего не делаем",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 12, OnFailure: failStrict, DueForRetry: true},
			"healthy"},
		{"канал только поднят, рукопожатия ещё нет — даём время",
			watchdogInput{Present: true, UpForSec: 5, OnFailure: failStrict, DueForRetry: true},
			"healthy"},
		{"строгий режим, канал мёртв, интервал вышел — переподнять",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 400, OnFailure: failStrict, DueForRetry: true, UpForSec: -1},
			"retry"},
		{"строгий режим, канал мёртв, интервал не вышел — ждать",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 400, OnFailure: failStrict, DueForRetry: false, UpForSec: -1},
			""},
		{"строгий режим, интерфейса нет вовсе — переподнять",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1},
			"retry"},
		{"выбран прямой выпуск, канал мёртв — выпустить",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 400, OnFailure: failDirect, DueForRetry: false, UpForSec: -1},
			"degrade"},
		{"уже выпущен напрямую, интервал вышел — пробуем вернуться",
			watchdogInput{Present: false, OnFailure: failDirect, Degraded: true, DueForRetry: true, UpForSec: -1},
			"recover"},
		{"уже выпущен напрямую, интервал не вышел — ждать",
			watchdogInput{Present: false, OnFailure: failDirect, Degraded: true, DueForRetry: false, UpForSec: -1},
			""},
		{"канал поднят давно, рукопожатия так и нет — мёртв",
			watchdogInput{Present: true, UpForSec: 211, StaleSec: 210, OnFailure: failStrict, DueForRetry: true},
			"retry"},

		{"канал вернулся сам, службы режима не применены — переприменить",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 12, OnFailure: failStrict, DueForRetry: true, ServicesPending: true, ReapplyDue: true},
			"reapply"},
		{"службы не применены, но прошлая попытка только что провалилась — подождать",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 12, OnFailure: failStrict, DueForRetry: true, ServicesPending: true, ReapplyDue: false},
			"healthy"},
		{"службы не применены, рукопожатия ещё нет — не трогать",
			watchdogInput{Present: true, UpForSec: 5, OnFailure: failStrict, DueForRetry: true, ServicesPending: true, ReapplyDue: true},
			"healthy"},
		{"службы не применены, но канал мёртв — сначала канал",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 400, OnFailure: failStrict, DueForRetry: true, UpForSec: -1, ServicesPending: true, ReapplyDue: true},
			"retry"},
		{"службы не применены при прямом выпуске — это не путь к выпуску",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 400, OnFailure: failDirect, DueForRetry: true, UpForSec: -1, ServicesPending: true, ReapplyDue: true},
			"degrade"},

		{"процесс сам переподключается — не трогать",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1, SelfRetrying: true},
			""},
		{"процесс сам переподключается, но канал ЖИВ — обычный здоровый путь",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 5, OnFailure: failStrict, DueForRetry: true, SelfRetrying: true},
			"healthy"},
		{"процесса нет — вступает сторож",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1, SelfRetrying: false},
			"retry"},
		{"процесс сам переподключается, но выбран прямой выпуск — выбор владельца выше",
			watchdogInput{Present: false, OnFailure: failDirect, DueForRetry: true, UpForSec: -1, SelfRetrying: true},
			"degrade"},

		{"молчит 200 с при пороге 210 — это ещё его собственный бюджет",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 200, StaleSec: 210, OnFailure: failStrict, DueForRetry: true},
			"healthy"},
		{"молчит 200 с при пороге 130 — бюджет вышел",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 200, StaleSec: 130, OnFailure: failStrict, DueForRetry: true, UpForSec: -1},
			"retry"},

		{"две неудачные попытки, подчинённый ещё повторяет — остановить его",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 2, CanPause: true, SelfRetrying: true},
			"pause"},
		{"одна неудачная попытка — бюджет ещё есть",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 1, CanPause: true},
			"retry"},
		{"бюджет исчерпан, остановка уже сделана — молчим, третья попытка человека",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 9, CanPause: true, SelfRetrying: true, Paused: true},
			""},
		{"служба отвергла запуск пределом частоты — сдался, молчим при любом числе попыток к серверу",

			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 0, CanPause: true, SelfRetrying: false, Paused: true},
			""},
		{"бюджет исчерпан, подчинённый уже сдался — НЕ трогать: это была бы третья попытка",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 9, CanPause: true, SelfRetrying: false},
			""},
		{"протокол останавливать не умеет — всё равно молчим, бюджет один на всех",
			watchdogInput{Present: false, OnFailure: failStrict, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 9, CanPause: false},
			""},
		{"бюджет исчерпан, но выбран прямой выпуск — выбор владельца выше",
			watchdogInput{Present: false, OnFailure: failDirect, DueForRetry: true, UpForSec: -1,
				ServerAttempts: 9, CanPause: true, SelfRetrying: true},
			"degrade"},

		{"переподключается сам, интерфейса нет, молчит меньше порога, режим напрямую — не трогать",
			watchdogInput{Present: false, SelfRetrying: true, UpForSec: 20, StaleSec: 130, OnFailure: failDirect,
				DueForRetry: true},
			"healthy"},
		{"переподключается сам, молчит дольше порога, режим напрямую — выпустить",
			watchdogInput{Present: false, SelfRetrying: true, UpForSec: 200, StaleSec: 130, OnFailure: failDirect,
				DueForRetry: true},
			"degrade"},
		{"интерфейса нет и никто не чинится — мёртв сразу",
			watchdogInput{Present: false, SelfRetrying: false, UpForSec: 5, StaleSec: 130, OnFailure: failStrict,
				DueForRetry: true},
			"retry"},

		{"две неудачи проверки при «живом по времени» канале — остановить сразу",
			watchdogInput{Present: true, SelfRetrying: true, UpForSec: 10, StaleSec: 130, OnFailure: failStrict,
				DueForRetry: true, ServerAttempts: serverAttemptBudget, CanPause: true},
			"pause"},
		{"канал жив, а счётчик старый — не трогать",
			watchdogInput{Present: true, HandshakeOK: true, AgeSec: 5, StaleSec: 210, OnFailure: failStrict,
				DueForRetry: true, ServerAttempts: 9, CanPause: true},
			"healthy"},
	}

	ladder := (&vpnApplier{}).ladder(context.Background(), &vpnState{})
	for _, c := range cases {
		got := ""
		if r := chooseRemedy(c.in, ladder); r != nil {
			got = r.id
		}
		if got != c.want {
			t.Errorf("%s: получено %q, ожидалось %q", c.name, got, c.want)
		}
	}
}

func TestSilentForTakesLaterMark(t *testing.T) {
	now, id := bootStamp()
	if id == "" {
		t.Skip("нет часов загрузки")
	}
	ago := func(s int) bootInstant { return now.Add(-time.Duration(s) * time.Second) }
	st := watchdogState{upSince: ago(7200), bootID: id, lastProof: ago(20), lastProofBoot: id}
	if got := silentFor(st); got < 19 || got > 25 {
		t.Fatalf("молчание от доказательства жизни: %d с, ожидалось ≈20", got)
	}
	st = watchdogState{upSince: ago(30), bootID: id, lastProof: ago(7200), lastProofBoot: id}
	if got := silentFor(st); got < 29 || got > 35 {
		t.Fatalf("канал только поднят: %d с, ожидалось ≈30", got)
	}
	st = watchdogState{upSince: ago(30), bootID: "другая-загрузка"}
	if got := silentFor(st); got != -1 {
		t.Fatalf("отметка чужой загрузки — не по чему судить, получено %d", got)
	}
}

func TestRestartKeepsMarks(t *testing.T) {
	prev := watchdogState{upSince: 100, bootID: "b", lastProof: 90, lastProofBoot: "b", Session: 7, SessionSince: 1700,
		alive: true, servicesPending: true}
	got := carryOverOnRestart(prev, watchdogState{Session: 5, backoff: time.Minute})
	if got.upSince != 100 || got.lastProof != 90 || got.Session != 7 || got.SessionSince != 1700 || !got.alive ||
		!got.servicesPending || got.backoff != time.Minute {
		t.Fatalf("перенос потерял отметки: %+v", got)
	}
	if got := carryOverOnRestart(watchdogState{Session: 3}, watchdogState{Session: 9, SessionSince: 5}); got.Session != 9 {
		t.Fatalf("номер сеанса не может уменьшиться: %+v", got)
	}
}

func TestSessionGrowsOnRevival(t *testing.T) {
	v := &vpnApplier{}
	v.noteLiveness(true)
	first := v.watch.Session
	v.noteLiveness(true)
	if v.watch.Session != first {
		t.Fatal("живой канал начал новый сеанс")
	}
	v.noteLiveness(false)
	v.noteLiveness(true)
	if v.watch.Session != first+1 || v.watch.SessionSince == 0 {
		t.Fatalf("возвращение к жизни не начало сеанс: %+v", v.watch)
	}
}

func TestUnknownProtocolIsRefused(t *testing.T) {
	v := &vpnApplier{drivers: map[vpndriver.Protocol]tunnelDriver{}}
	d := v.driver(&vpnState{Plan: vpnPlan{Protocol: "ikev2"}})
	if _, ok := d.(unknownDriver); !ok {
		t.Fatalf("неизвестный протокол получил драйвер %T", d)
	}
	if _, aerr := d.up(upRequest{}); aerr == nil {
		t.Fatal("неизвестный протокол поднялся")
	}
	if d.iface() == "" || d.present() {
		t.Fatal("имя интерфейса пустое или канал «есть»: пробы потеряли бы привязку")
	}
}

func TestStrictModeNeverDegrades(t *testing.T) {
	ladder := (&vpnApplier{}).ladder(context.Background(), &vpnState{})
	for _, present := range []bool{true, false} {
		for _, hs := range []bool{true, false} {
			for _, age := range []int64{0, 100, 10000} {
				for _, due := range []bool{true, false} {
					for _, paused := range []bool{true, false} {
						for _, self := range []bool{true, false} {
							for _, dataDead := range []bool{true, false} {
								in := watchdogInput{Present: present, HandshakeOK: hs, AgeSec: age,
									UpForSec: -1, OnFailure: failStrict, DueForRetry: due,
									Paused: paused, SelfRetrying: self, ServerAttempts: 9, CanPause: true,
									DataDead: dataDead}
								if r := chooseRemedy(in, ladder); r != nil && r.id == "degrade" {
									t.Fatalf("строгий режим выпустил трафик напрямую: %+v", in)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	v := &vpnApplier{}
	v.watch.backoff = retryMin
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		v.growBackoff()
		seen[v.watch.backoff.String()] = true
		if v.watch.backoff > retryMax {
			t.Fatalf("интервал перерос потолок: %s", v.watch.backoff)
		}
	}
	if v.watch.backoff != retryMax {
		t.Fatalf("интервал обязан дорасти до потолка, получено %s", v.watch.backoff)
	}
	v.resetBackoff()
	if v.watch.backoff != retryMin || !v.watch.nextTry.IsZero() {
		t.Fatal("после оживания канала интервал обязан сбрасываться")
	}
}

func TestProfilePathRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../../etc/shadow", "a/b", "", ".", "..", "Ключ", "a b"} {
		if _, err := profilePath(bad); err == nil {
			t.Errorf("путь профиля принял %q — это выход из каталога", bad)
		}
	}
	got, err := profilePath("ofis-kiev")
	if err != nil || got != "/etc/wireguard/vpn-panel-ofis-kiev.conf" {
		t.Fatalf("путь профиля: %q, %v", got, err)
	}
}

func TestNeverAsksForKeyDump(t *testing.T) {
	files, _ := os.ReadDir(".")
	for _, f := range files {
		if !strings.HasPrefix(f.Name(), "vpn") || !strings.HasSuffix(f.Name(), ".go") ||
			strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(f.Name()) //nolint:gosec
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`"dump"|show[^\n]*dump`).Find(data) != nil {
			t.Fatalf("%s: сводка с секретным ключом запрашиваться не должна", f.Name())
		}
		if regexp.MustCompile(`log\.Printf\([^)]*PrivateKey`).Find(data) != nil {
			t.Fatalf("%s: секретный ключ не пишется в журнал", f.Name())
		}
	}
}

func TestMTUProbeLimits(t *testing.T) {
	if probeMTUMaxSteps > 16 || probeMTUTimeout.Seconds() > 60 || probeMTUStepWait > 2 {
		t.Fatal("пределы подбора размера пакетов выше согласованных потолков")
	}
}

func TestOutgoingInterfaceChangeForcesRestart(t *testing.T) {
	white := []byte("server:\n    interface: 127.0.0.1\n    prefetch: yes\n")
	black := []byte("server:\n    interface: 127.0.0.1\n    outgoing-interface: 10.66.66.2\n    do-ip6: no\n    prefetch: yes\n")
	other := []byte("server:\n    interface: 127.0.0.1\n    outgoing-interface: 10.66.66.9\n    do-ip6: no\n    prefetch: yes\n")

	if !outgoingChanged(white, black) {
		t.Fatal("включение защищённого режима обязано требовать перезапуска")
	}
	if !outgoingChanged(black, white) {
		t.Fatal("возврат к прямому доступу обязан требовать перезапуска")
	}
	if !outgoingChanged(black, other) {
		t.Fatal("смена адреса канала обязана требовать перезапуска")
	}
	if outgoingChanged(black, black) {
		t.Fatal("без изменений перезапуск не нужен — он рвёт кэш имён")
	}

	sameOutgoing := []byte("server:\n    interface: 127.0.0.1\n    interface: 192.168.11.1\n    outgoing-interface: 10.66.66.2\n    do-ip6: no\n")
	if outgoingChanged(black, sameOutgoing) {
		t.Fatal("правка не про привязку не должна рвать кэш имён")
	}
}

func TestAgentKillSwitchIsStrictByDefault(t *testing.T) {
	for _, raw := range []string{"", "strict", "STRICT", "Direct", "direct ", "0", "null", "прямой"} {
		if got := normalizeOnFailure(raw); got != failStrict {
			t.Errorf("значение %q дало %q — ожидался строгий запрет", raw, got)
		}
	}
	if got := normalizeOnFailure(failDirect); got != failDirect {
		t.Fatalf("осознанный выбор администратора обязан сохраняться, получено %q", got)
	}
}

func TestRouteGetIsAskedWithMark(t *testing.T) {
	got := strings.Join(routeGetArgs("192.0.2.10", 51820), " ")
	if got != "-j route get 192.0.2.10 mark 51820" {
		t.Fatalf("аргументы: %q", got)
	}
}

func TestUnitStateDecidesWhoActs(t *testing.T) {
	for _, c := range []struct {
		state           string
		running, loaded bool
	}{
		{"active", true, true},
		{"activating", true, true},
		{"reloading", true, true},
		{"deactivating", true, true},
		{"failed", false, true},
		{"inactive", false, false},
		{"", false, false},
	} {
		if got := unitRunningFrom(c.state); got != c.running {
			t.Fatalf("%q: сам себя ведёт = %v, ждали %v", c.state, got, c.running)
		}
		if got := unitLoadedFrom(c.state); got != c.loaded {
			t.Fatalf("%q: держать сессию = %v, ждали %v", c.state, got, c.loaded)
		}
	}
}

func TestTunnelMTUFromDevGuardsAgainstTunnels(t *testing.T) {
	kinds := map[string]string{"ens3": "", "ovpn-vpn0": "ovpn", "wg-vpn0": "wireguard", "ppp0": "ppp"}
	mtus := map[string]int{"ens3": 1500, "ovpn-vpn0": 1448, "wg-vpn0": 1420, "ppp0": 1492}
	kindOf := func(d string) string { return kinds[d] }
	mtuOf := func(d string) int { return mtus[d] }
	cases := []struct {
		dev      string
		overhead int
		want     int
		noted    bool
	}{
		{"ens3", 52, 1448, false},
		{"ppp0", 52, 1440, false},
		{"ens3", 132, 1368, false},
		{"ovpn-vpn0", 52, 1448, true},
		{"wg-vpn0", 52, 1448, true},
		{"", 52, 1448, true},
	}
	for _, c := range cases {
		got, note := tunnelMTUFromDev(c.dev, kindOf, mtuOf, c.overhead)
		if got != c.want || (note != "") != c.noted {
			t.Errorf("%q/%d: %d %q, ожидали %d noted=%v", c.dev, c.overhead, got, note, c.want, c.noted)
		}
	}
}
