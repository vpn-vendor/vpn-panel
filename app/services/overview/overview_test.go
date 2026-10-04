package overview

import (
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/internal/pathprobe"
)

func TestInternetNeverClaimsWithoutEvidence(t *testing.T) {
	for name, paths := range map[string][]pathmon.Snapshot{
		"путей нет":           nil,
		"проб ещё не было":    {{Kind: pathmon.Direct, State: pathprobe.Unknown}},
		"цель молчит":         {{Kind: pathmon.Direct, State: pathprobe.NoAnswer}},
		"путь другого режима": {{Kind: pathmon.Tunnel, State: pathprobe.Up}},
	} {
		if l := Internet(false, paths); l.Level != Unknown || l.Text != l.TextUnknown {
			t.Errorf("%s: %q (%q)", name, l.Level, l.Text)
		}
	}
}

func TestInternetByPathStateAndLoss(t *testing.T) {
	up := func(loss float64, known bool) []pathmon.Snapshot {
		return []pathmon.Snapshot{{Kind: pathmon.Direct, State: pathprobe.Up, LossPct: loss, LossKnown: known}}
	}
	cases := []struct {
		paths []pathmon.Snapshot
		want  Level
	}{
		{up(0, false), OK}, {up(0.3, true), OK}, {up(1, true), Warn}, {up(2.9, true), Warn}, {up(3, true), Bad},
		{[]pathmon.Snapshot{{Kind: pathmon.Direct, State: pathprobe.Down}}, Bad},
	}
	for _, c := range cases {
		if got := Internet(false, c.paths).Level; got != c.want {
			t.Errorf("%+v: %q, ждали %q", c.paths[0], got, c.want)
		}
	}

	l := Internet(true, []pathmon.Snapshot{
		{Kind: pathmon.Tunnel, State: pathprobe.Up, LossPct: 0.1, LossKnown: true},
		{Kind: pathmon.Beyond, State: pathprobe.Up, LossPct: 1.5, LossKnown: true},
		{Kind: pathmon.Direct, State: pathprobe.Down},
	})
	if l.Level != Warn || l.Row != pathmon.RowTunnelLoss || l.AliveRow != pathmon.RowTunnelRTT || l.TextDown == "" {
		t.Errorf("защищённый режим: %q по ряду %q", l.Level, l.Row)
	}
	if down := Internet(true, []pathmon.Snapshot{{Kind: pathmon.Tunnel, State: pathprobe.Down}}); down.Level != Bad || down.Text == down.TextBad {
		t.Errorf("обрыв канала обязан называться обрывом: %q", down.Text)
	}
}

func TestVoiceNormBelongsToTheQueue(t *testing.T) {
	slow := metrics.VoiceNorm{TargetMs: 18.2, IntervalMs: 113.2}
	if l := Voice(false, slow, true, 12, true); l.Level != OK || l.Warn != 18.2 || l.Bad != 113.2 || l.Row != metrics.RowWANVoiceDelay {
		t.Errorf("медленный канал: 12 мс при цели 18,2 — норма: %+v", l)
	}
	if l := Voice(true, metrics.VoiceNorm{TargetMs: 5, IntervalMs: 100}, true, 12, true); l.Level != Warn || l.Row != metrics.RowTunnelVoiceDelay {
		t.Errorf("12 мс при цели 5 — внимание: %+v", l)
	}
	if l := Voice(false, slow, true, 0, false); l.Level != Unknown || l.Row == "" {
		t.Errorf("нормы есть, значения нет — «нет данных», но фраза живёт: %+v", l)
	}
	if l := Voice(false, metrics.VoiceNorm{}, false, 1, true); l.Level != Unknown || l.Row != "" {
		t.Errorf("очереди нет — фраза статична: %+v", l)
	}
}

func TestLoadUsesTheSameLimitsAsFuses(t *testing.T) {
	if l := Load(metrics.Protect{}, 70, 50); l.Level != Unknown {
		t.Errorf("нет данных датчиков: %q", l.Level)
	}
	cases := []struct {
		busy, psi float64
		want      Level
	}{{20, 0, OK}, {70, 0, Warn}, {84, 0, Warn}, {85, 0, Bad}, {10, 50, Warn}, {90, 60, Bad}}
	for _, c := range cases {
		l := Load(metrics.Protect{OK: true, CPUBusy: c.busy, PressureCPU: c.psi}, 70, 50)
		if l.Level != c.want {
			t.Errorf("загрузка %v, давление %v: %q, ждали %q", c.busy, c.psi, l.Level, c.want)
		}
	}

	if l := Load(metrics.Protect{OK: true}, 60, 50); l.Warn != 60 || l.Bad != 80 {
		t.Errorf("пороги обязаны выводиться из предела предохранителя: %+v", l)
	}
}

func TestRowsFollowTheMode(t *testing.T) {
	if r := RowsFor(true); r.Rx != metrics.RowTunnelRx || r.VoiceDelay != metrics.RowTunnelVoiceDelay || r.Loss != pathmon.RowTunnelLoss {
		t.Errorf("защищённый режим: %+v", r)
	}
	if r := RowsFor(false); r.Rx != metrics.RowWANRx || r.VoiceDelay != metrics.RowWANVoiceDelay || r.Loss != pathmon.RowDirectLoss {
		t.Errorf("прямой доступ: %+v", r)
	}
}

func TestLightsCarryOwnerAndAdvice(t *testing.T) {
	lights := []Light{
		Internet(true, nil), Internet(false, nil),
		Voice(true, metrics.VoiceNorm{TargetMs: 5, IntervalMs: 100}, true, 1, true),
		Voice(false, metrics.VoiceNorm{}, false, 0, false),
		Load(metrics.Protect{OK: true, CPUBusy: 99}, 70, 50),
	}
	for _, l := range lights {
		if l.Owner == "" || l.Advice == "" || l.AdviceOK == "" || l.AdviceWarn == "" || l.AdviceBad == "" || l.AdviceUnknown == "" {
			t.Errorf("светофор «%s»: владелец %q, советы неполны", l.Text, l.Owner)
		}
	}
	down := Internet(true, []pathmon.Snapshot{{Kind: pathmon.Tunnel, State: pathprobe.Down}})
	if down.Advice != down.AdviceDown || down.AdviceDown == "" {
		t.Fatalf("у «не отвечает» свой совет: %q", down.Advice)
	}
	if bad := Load(metrics.Protect{OK: true, CPUBusy: 99}, 70, 50); bad.Level != Bad || bad.Advice != bad.AdviceBad {
		t.Fatalf("совет не совпал с уровнем: %+v", bad)
	}
}
