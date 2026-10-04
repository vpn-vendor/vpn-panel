package vpncheck

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestEchoRequestIsWellFormed(t *testing.T) {
	b := EchoRequest(0x1234, 7, 24)
	if len(b) != HeaderLen+24 {
		t.Fatalf("длина пакета %d, ожидалось %d", len(b), HeaderLen+24)
	}
	if b[0] != icmpEchoRequest {
		t.Errorf("тип пакета %d, ожидался эхо-запрос", b[0])
	}
	if got := binary.BigEndian.Uint16(b[4:6]); got != 0x1234 {
		t.Errorf("метка отправителя %#x", got)
	}

	if got := checksum(b); got != 0 {
		t.Errorf("контрольная сумма не сходится: %#x", got)
	}
}

func TestParseEchoReplyMatchesOurProbeOnly(t *testing.T) {
	reply := EchoRequest(0x1234, 9, 0)
	reply[0] = icmpEchoReply
	kind, seq, err := ParseReply(reply, 0x1234)
	if err != nil || kind != ReplyEcho || seq != 9 {
		t.Fatalf("свой ответ не опознан: kind=%v seq=%d err=%v", kind, seq, err)
	}
	if kind, _, _ := ParseReply(reply, 0x9999); kind != ReplyOther {
		t.Error("чужая проба принята за свою — в общем сокете это исказит все числа")
	}
}

func TestParseTimeExceededFindsOurProbeInside(t *testing.T) {
	orig := EchoRequest(0xabcd, 3, 0)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	msg := append([]byte{icmpTimeExceeded, 0, 0, 0, 0, 0, 0, 0}, append(ipHdr, orig[:HeaderLen]...)...)

	kind, seq, err := ParseReply(msg, 0xabcd)
	if err != nil || kind != ReplyExpired || seq != 3 {
		t.Fatalf("истёкшее время жизни не разобрано: kind=%v seq=%d err=%v", kind, seq, err)
	}
	if kind, _, _ := ParseReply(msg, 0x1111); kind != ReplyOther {
		t.Error("чужой пакет внутри принят за свой")
	}
}

func TestParseReplySurvivesTruncatedInput(t *testing.T) {
	inputs := [][]byte{
		{},
		{icmpEchoReply},
		{icmpTimeExceeded, 0, 0, 0, 0, 0, 0, 0},
		append([]byte{icmpTimeExceeded, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 10)...),
		append([]byte{icmpTimeExceeded, 0, 0, 0, 0, 0, 0, 0}, append([]byte{0x45}, make([]byte, 19)...)...),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("вход %d уронил разбор: %v", i, r)
				}
			}()
			_, _, _ = ParseReply(in, 1)
		}()
	}
}

func TestSummarizeCountsLossAndJitter(t *testing.T) {
	rtts := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 15 * time.Millisecond}
	st := Summarize(4, rtts)
	if st.Received != 3 || st.Sent != 4 {
		t.Fatalf("получено %d из %d", st.Received, st.Sent)
	}
	if st.LossPct != 25 {
		t.Errorf("потери %.1f %%, ожидалось 25", st.LossPct)
	}
	if st.AvgMs != 15 || st.MinMs != 10 || st.MaxMs != 20 {
		t.Errorf("задержка avg=%.1f min=%.1f max=%.1f", st.AvgMs, st.MinMs, st.MaxMs)
	}

	if st.JitterMs != 7.5 {
		t.Errorf("джиттер %.2f, ожидалось 7.5", st.JitterMs)
	}
}

func TestSummarizeWithoutAnswersIsNotAVerdict(t *testing.T) {
	st := Summarize(10, nil)
	if st.LossPct != 100 || st.AvgMs != 0 {
		t.Errorf("проба без ответов: %+v", st)
	}
	if got := Summarize(0, nil); got.LossPct != 0 {
		t.Error("ноль отправленных — это «не измеряли», а не «сто процентов потерь»")
	}
}

func TestSampleThresholdDependsOnProbeKind(t *testing.T) {
	if MinSamples(KindVoice) != 1000 {
		t.Error("голосовая проба обязана требовать 1000 пакетов")
	}
	for _, k := range []Kind{KindEcho, KindConnection} {
		if MinSamples(k) != 100 {
			t.Errorf("проба %s: порог %d, ожидалось 100", k, MinSamples(k))
		}
		if !Trustworthy(k, 100) {
			t.Errorf("проба %s: 100 измерений признаны недостаточными", k)
		}
		if Trustworthy(k, 99) {
			t.Errorf("проба %s: 99 измерений признаны достаточными", k)
		}
	}
	if Trustworthy(KindVoice, 999) {
		t.Error("голосовая проба на 999 пакетах не может быть достоверной")
	}
}

func TestSampleNoteAlwaysNamesTheCount(t *testing.T) {
	if got := SampleNote(KindConnection, 100); got != "по 100 измерениям" {
		t.Errorf("строка достоверности: %q", got)
	}
	if got := SampleNote(KindConnection, 40); !strings.Contains(got, "40") || !strings.Contains(got, "мало") {
		t.Errorf("короткая выборка обязана честно называться короткой: %q", got)
	}
	if got := SampleNote(KindEcho, 0); got != "измерить не удалось" {
		t.Errorf("несостоявшаяся проба: %q", got)
	}
}

func TestReportFactsAreSilentAboutFailedSteps(t *testing.T) {
	r := Report{
		Service:   Probe{Kind: KindEcho, Err: "измерить не удалось: нет прав"},
		Data:      Probe{Kind: KindConnection, Stats: Summarize(100, repeat(100, 30*time.Millisecond))},
		DirectLeg: Probe{Kind: KindEcho, Stats: Summarize(100, repeat(100, 70*time.Millisecond))},
		TunnelLeg: Probe{Kind: KindEcho, Err: "измерить не удалось"},
		Queue:     QueueDrops{Err: "счётчики не прочитаны"},
	}
	_, serviceLoss, dataLoss, rttBase, rttTunnel, sample, dropped, tunDown, dirDown := r.Facts()
	if serviceLoss != 0 {
		t.Error("провалившаяся проба дала число — это ложный вердикт")
	}
	if dataLoss != 0 || sample != 100 {
		t.Errorf("удачная проба потеряна: loss=%.2f sample=%d", dataLoss, sample)
	}
	if rttBase == 0 {
		t.Error("прямое плечо измерено, а в фактах его нет")
	}
	if rttTunnel != 0 || dropped != 0 || tunDown != 0 || dirDown != 0 {
		t.Error("неизмеренное попало в факты")
	}
}

func repeat(n int, d time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func TestBurstsCountConsecutiveLosses(t *testing.T) {
	recv := map[int]bool{0: true, 1: true, 4: true, 5: true, 9: true}

	maxBurst, events := Bursts(10, recv)
	if maxBurst != 3 || events != 2 {
		t.Fatalf("самая длинная пачка %d, случаев %d; ожидалось 3 и 2", maxBurst, events)
	}
}

func TestSingleLossesAreNotBursts(t *testing.T) {
	recv := map[int]bool{0: true, 2: true, 4: true, 6: true, 8: true}
	maxBurst, events := Bursts(9, recv)
	if events != 0 {
		t.Errorf("одиночные пропуски посчитаны пачками: случаев %d", events)
	}
	if maxBurst != 1 {
		t.Errorf("самая длинная череда %d, ожидалась 1", maxBurst)
	}
}

func TestBurstsOnCleanRun(t *testing.T) {
	recv := map[int]bool{0: true, 1: true, 2: true}
	if mb, ev := Bursts(3, recv); mb != 0 || ev != 0 {
		t.Errorf("на чистом прогоне пачек быть не может: %d/%d", mb, ev)
	}
}

func TestGradeFollowsIndustryBands(t *testing.T) {
	target := Stats{Sent: 100, Received: 100, LossPct: 0.0, JitterMs: 1.1, AvgMs: 36}
	if g, _ := GradeVoice(target); g != GradeTarget {
		t.Errorf("канал уровня оператора отнесён к полосе %q", g)
	}
	ok := Stats{Sent: 100, Received: 99, LossPct: 0.9, JitterMs: 25, AvgMs: 200}
	if g, _ := GradeVoice(ok); g != GradeOK {
		t.Errorf("пригодный канал отнесён к полосе %q", g)
	}

	bad := Stats{Sent: 1498, Received: 1281, LossPct: 14.49, JitterMs: 1.9, AvgMs: 208}
	if g, _ := GradeVoice(bad); g != GradeBad {
		t.Errorf("рвущийся канал отнесён к полосе %q", g)
	}
	if g, why := GradeVoice(Stats{}); g != GradeUnknown || why == "" {
		t.Error("неизмеренная проба не может иметь полосу качества")
	}
}

func TestBurstNoteSpeaksHumanly(t *testing.T) {
	clean := Stats{Sent: 100, Received: 100}
	if BurstNote(clean) != "" {
		t.Error("на чистом прогоне говорить не о чем")
	}
	single := Stats{Sent: 100, Received: 98, BurstEvents: 0, MaxBurst: 1}
	if !strings.Contains(BurstNote(single), "одиночные") {
		t.Errorf("одиночные потери описаны неверно: %q", BurstNote(single))
	}
	burst := Stats{Sent: 100, Received: 90, BurstEvents: 3, MaxBurst: 5}
	note := BurstNote(burst)
	if !strings.Contains(note, "пачками") || !strings.Contains(note, "5") {
		t.Errorf("пачки потерь описаны неверно: %q", note)
	}
}

func TestBlackholeNeedsSmallOKAndLargeLost(t *testing.T) {
	blackhole := Report{
		Service: Probe{Kind: KindEcho, Stats: Summarize(100, repeat(97, 20*time.Millisecond))},
		Large:   Probe{Kind: KindEcho, Stats: Summarize(10, nil)},
	}
	if !blackhole.Blackhole() {
		t.Error("мелкие ходят, крупные пропали — это и есть чёрная дыра")
	}

	healthy := Report{
		Service: Probe{Kind: KindEcho, Stats: Summarize(100, repeat(100, 20*time.Millisecond))},
		Large:   Probe{Kind: KindEcho, Stats: Summarize(10, repeat(10, 21*time.Millisecond))},
	}
	if healthy.Blackhole() {
		t.Error("здоровый путь объявлен чёрной дырой")
	}

	badPath := Report{
		Service: Probe{Kind: KindEcho, Stats: Summarize(100, repeat(40, 20*time.Millisecond))},
		Large:   Probe{Kind: KindEcho, Stats: Summarize(10, nil)},
	}
	if badPath.Blackhole() {
		t.Error("общие потери — не чёрная дыра, у них свой ответ")
	}

	unmeasured := Report{Service: Probe{Kind: KindEcho, Err: "не удалось"}}
	if unmeasured.Blackhole() {
		t.Error("без измерений вердикта быть не может")
	}
}

func TestSizeProbeHasItsOwnVerdict(t *testing.T) {
	lost := Stats{Sent: 10, Received: 0, LossPct: 100}
	g, why := GradeProbe(KindSize, lost)
	if g != GradeBlocked || !strings.Contains(why, "не проходят") {
		t.Errorf("непрошедший крупный кадр описан неверно: %s / %s", g, why)
	}
	ok := Stats{Sent: 10, Received: 10, LossPct: 0}
	if g, _ := GradeProbe(KindSize, ok); g != GradeThrough {
		t.Errorf("прошедший крупный кадр отнесён к полосе %q", g)
	}
	if MinSamples(KindSize) != 10 {
		t.Error("пробе размера сотня измерений не нужна — она отвечает «проходит или нет»")
	}

	voice := Stats{Sent: 100, Received: 100, LossPct: 0, JitterMs: 1, AvgMs: 36}
	if g, _ := GradeProbe(KindEcho, voice); g != GradeTarget {
		t.Errorf("голосовая проба сломана: %q", g)
	}
}
