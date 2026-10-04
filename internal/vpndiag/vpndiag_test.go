package vpndiag

import (
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

func has(out []Finding, code string) *Finding {
	for i := range out {
		if out[i].Code == code {
			return &out[i]
		}
	}
	return nil
}

func mustHave(t *testing.T, out []Finding, code, why string) *Finding {
	t.Helper()
	f := has(out, code)
	if f == nil {
		t.Fatalf("%s: вердикта %q нет среди ответов каталога: %+v", why, code, out)
	}
	return f
}

func healthy() Facts {
	return Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, HandshakeAgeSec: 12, FullTunnel: true, Cores: 2, Load1: 0.1}
}

func TestHealthyTunnelSaysSoOutLoud(t *testing.T) {
	out := Analyze(healthy())
	if has(out, "tunnel_ok") == nil {
		t.Fatalf("исправный канал обязан подтверждаться вслух: %+v", out)
	}
	for _, f := range out {
		if f.Level == LevelError {
			t.Fatalf("на исправном канале не должно быть срочных вердиктов: %+v", f)
		}
	}
}

func TestRealFieldCase_PathIsTheLimit(t *testing.T) {
	f := healthy()
	f.DirectDownKbit, f.TunnelDownKbit = 82800, 37800
	f.TariffDownKbit, f.ShapedTunDownKbit = 100000, 90000
	f.QueueDropped = 0
	f.Load1 = 0.07

	out := Analyze(f)
	got := mustHave(t, out, "path_ceiling", "каталог обязан указать на путь до поставщика")
	if !strings.Contains(got.Text, "не отбросили ни одного пакета") {
		t.Fatalf("вердикт обязан предъявлять доказательство невиновности сервера: %q", got.Text)
	}

	if has(out, "cpu_bound") != nil || has(out, "our_queue_drops") != nil {
		t.Fatalf("невиновные причины названы виновными: %+v", out)
	}
}

func TestOurOwnShaperIsNamedFirst(t *testing.T) {
	f := healthy()
	f.TariffDownKbit, f.ShapedTunDownKbit = 50000, 45000
	f.DirectDownKbit, f.TunnelDownKbit = 82800, 44000

	out := Analyze(f)
	got := mustHave(t, out, "our_shaper", "собственное ограничение обязано называться")
	if got.Level != LevelInfo {
		t.Fatalf("это не поломка, а настройка — уровень %q", got.Level)
	}
	if has(out, "path_ceiling") != nil {
		t.Fatal("нельзя обвинять путь, когда режет собственная очередь")
	}
}

func TestRedIndicatorExplained(t *testing.T) {
	f := healthy()
	f.SampleSize = 2994
	f.ServiceLossPct, f.DataLossPct = 1.67, 0.23

	got := mustHave(t, Analyze(f), "icmp_deprioritized",
		"расхождение служебных пакетов и голоса обязано объясняться")

	if !strings.Contains(got.Title, "не всегда признак плохого звука") {
		t.Fatalf("заголовок обязан снимать тревогу и не обещать лишнего: %q", got.Title)
	}
}

func TestShortSampleRefusesVerdict(t *testing.T) {
	f := healthy()
	f.SampleSize = 60
	f.ServiceLossPct, f.DataLossPct = 1.67, 0.0

	out := Analyze(f)
	if has(out, "sample_small") == nil {
		t.Fatal("на короткой выборке каталог обязан признать нехватку данных")
	}
	if has(out, "icmp_deprioritized") != nil {
		t.Fatal("вердикт по шуму выносить нельзя")
	}
}

func TestLatencyBlamedOnGeographyNotTunnel(t *testing.T) {
	f := healthy()
	f.RTTBaselineMs, f.RTTTunnelMs = 73.9, 71.1

	got := mustHave(t, Analyze(f), "latency_geography",
		"надо объяснить, что задержку добавил не канал")
	if got.Level != LevelInfo {
		t.Fatalf("это не проблема: уровень %q", got.Level)
	}
}

func TestUnknownDataPlaneDoesNotAccuseTheChannel(t *testing.T) {
	f := healthy()
	f.DataPlane = vpndriver.Unknown
	out := Analyze(f)
	if has(out, "data_dead") != nil {
		t.Fatalf("Unknown обвинил канал в мёртвых данных: %+v", out)
	}
	if has(out, "tunnel_ok") == nil {
		t.Fatal("при неизвестной пробе исправный канал обязан подтверждаться, а не обвиняться")
	}

	f.DataPlane = vpndriver.No
	if has(Analyze(f), "data_dead") == nil {
		t.Fatal("точное No обязано давать вердикт «данные не идут»")
	}
}

func TestBrokenStates(t *testing.T) {
	cases := map[string]func(Facts) Facts{
		"released":        func(f Facts) Facts { f.Degraded = true; return f },
		"data_dead":       func(f Facts) Facts { f.DataPlane = vpndriver.No; return f },
		"handshake_lost":  func(f Facts) Facts { f.Online = false; return f },
		"handshake_never": func(f Facts) Facts { f.Online, f.HandshakeEver = false, false; return f },
		"no_tunnel":       func(f Facts) Facts { f.Present, f.Online = false, false; return f },
		"reconnecting":    func(f Facts) Facts { f.Present, f.Online, f.SelfHealing = false, false, true; return f },
		"data_stuck":      func(f Facts) Facts { f.DataStuck = true; return f },
	}
	for code, mut := range cases {
		out := Analyze(mut(healthy()))
		got := has(out, code)
		if got == nil {
			t.Errorf("%s: вердикт отсутствует: %+v", code, out)
			continue
		}
		if got.Level != LevelError {
			t.Errorf("%s: уровень %q, ожидался срочный", code, got.Level)
		}
		if out[0].Code != code {
			t.Errorf("%s: срочный вердикт обязан быть первым, первым идёт %q", code, out[0].Code)
		}
	}
}

func TestNoTunnelSaysWhenRetriesStopped(t *testing.T) {
	f := healthy()
	f.Present, f.Online = false, false
	if got := has(Analyze(f), "no_tunnel"); got == nil || strings.Contains(got.Text, "прекратила") {
		t.Fatalf("без остановки текст не должен говорить о прекращении попыток: %+v", got)
	}
	f.RetryPaused = true
	got := has(Analyze(f), "no_tunnel")
	if got == nil || !strings.Contains(got.Text, "прекратила автоматические попытки") {
		t.Fatalf("остановка сторожа не названа: %+v", got)
	}
	if !strings.Contains(got.Action, "Применить") {
		t.Fatalf("действие администратора потеряно: %+v", got)
	}
}

func TestSelfHealingIsNotNoTunnel(t *testing.T) {
	f := healthy()
	f.Present, f.Online, f.SelfHealing = false, false, true
	out := Analyze(f)
	if has(out, "no_tunnel") != nil || has(out, "reconnecting") == nil {
		t.Fatalf("самопочинка названа отсутствием канала: %+v", out)
	}
	if got := has(out, "reconnecting"); strings.Contains(got.Action, "Применить") {
		t.Fatalf("во время самопочинки совет нажать кнопку ложен: %+v", got)
	}
	f.RetryPaused = true
	if has(Analyze(f), "no_tunnel") == nil {
		t.Fatal("остановленные попытки — снова «канал не поднят» с кнопкой")
	}
}

func TestNoMeasurementsNoSpeedVerdicts(t *testing.T) {
	out := Analyze(healthy())
	for _, code := range []string{"path_ceiling", "our_shaper", "cpu_bound", "our_queue_drops"} {
		if has(out, code) != nil {
			t.Errorf("без замеров вердикт %q выдуман", code)
		}
	}
}

func TestEveryFindingIsHumanAndActionable(t *testing.T) {
	var all []Finding
	variants := []Facts{
		healthy(),
		func() Facts { f := healthy(); f.Degraded = true; return f }(),
		func() Facts { f := healthy(); f.DataPlane = vpndriver.No; return f }(),
		func() Facts { f := healthy(); f.Present, f.Online, f.HandshakeEver = true, false, false; return f }(),
		func() Facts {
			f := healthy()
			f.DirectDownKbit, f.TunnelDownKbit, f.ShapedTunDownKbit = 82800, 37800, 90000
			f.Cores, f.Load1, f.QueueDropped = 2, 1.9, 12
			return f
		}(),
		func() Facts {
			f := healthy()
			f.SampleSize, f.ServiceLossPct, f.DataLossPct = 2000, 3.0, 0.1
			f.RTTBaselineMs, f.RTTTunnelMs, f.Blackhole = 70, 72, true
			f.FullTunnel, f.ConfigDNS = false, "8.8.8.8"
			return f
		}(),
	}
	for _, v := range variants {
		all = append(all, Analyze(v)...)
	}
	if len(all) < 12 {
		t.Fatalf("каталог подозрительно беден: %d ответов", len(all))
	}
	seen := map[string]bool{}
	for _, f := range all {
		if f.Title == "" || f.Text == "" {
			t.Errorf("%s: пустой заголовок или текст", f.Code)
		}
		if !strings.ContainsFunc(f.Title+f.Text, isCyrillic) {
			t.Errorf("%s: текст не по-русски", f.Code)
		}

		if f.Level != LevelOK && f.Action == "" {
			t.Errorf("%s: вердикт не говорит, что делать", f.Code)
		}
		for _, bad := range []string{"nftables", "wireguard", "WireGuard", "systemd", "unbound", "CAKE", "MTU "} {
			if strings.Contains(f.Title+f.Text+f.Action, bad) {
				t.Errorf("%s: в тексте для администратора внутренняя кухня «%s»", f.Code, bad)
			}
		}
		seen[f.Code] = true
	}
	if len(seen) < 10 {
		t.Fatalf("покрыто мало правил каталога: %d", len(seen))
	}
}

func isCyrillic(r rune) bool { return r >= 'А' && r <= 'я' }

func TestGuardIsVisibleWhenWorking(t *testing.T) {
	got := Analyze(Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, OutboundGuard: true, BlockedOutbound: 21})
	f := has(got, "outbound_blocked")
	if f == nil {
		t.Fatal("сработавшая защита не показана администратору")
	}
	if !strings.Contains(f.Title, "21 попытку") {
		t.Errorf("число попыток не названо человеческим языком: %q", f.Title)
	}
}

func TestGuardIsVisibleWhenMissing(t *testing.T) {
	got := Analyze(Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, OutboundGuard: false})
	f := has(got, "outbound_guard_off")
	if f == nil {
		t.Fatal("отсутствие защиты выхода молчаливо — администратор считает, что анонимность есть")
	}
	if f.Level != LevelWarn || f.Action == "" {
		t.Errorf("предупреждение обязано говорить, что делать: %+v", f)
	}
}

func TestGuardSilentWithoutAttempts(t *testing.T) {
	got := Analyze(Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, OutboundGuard: true, BlockedOutbound: 0})
	if has(got, "outbound_blocked") != nil {
		t.Error("ноль попыток — говорить не о чем")
	}
}

func TestGuardSilentInWhiteMode(t *testing.T) {
	got := Analyze(Facts{ModeBlack: false, OutboundGuard: false})
	for _, code := range []string{"outbound_blocked", "outbound_guard_off"} {
		if has(got, code) != nil {
			t.Errorf("в прямом режиме правило %s не применяется", code)
		}
	}
}

func TestPluralFormsAreRussian(t *testing.T) {
	cases := map[int64]string{1: "попытку", 2: "попытки", 4: "попытки", 5: "попыток",
		11: "попыток", 12: "попыток", 21: "попытку", 22: "попытки", 25: "попыток", 111: "попыток"}
	for n, want := range cases {
		if got := plural(n, "попытку", "попытки", "попыток"); got != want {
			t.Errorf("%d: %q, ожидалось %q", n, got, want)
		}
	}
}

func TestSampleThresholdComesFromTheProbe(t *testing.T) {
	facts := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, SampleSize: 100, SampleMin: 100,
		ServiceLossPct: 0, DataLossPct: 0}
	if has(Analyze(facts), "sample_small") != nil {
		t.Error("сто измерений пробы соединениями — достаточная выборка")
	}

	voice := facts
	voice.SampleMin = 0
	f := has(Analyze(voice), "sample_small")
	if f == nil {
		t.Fatal("сто пакетов голосовой пробы обязаны считаться недостаточными")
	}
	if !strings.Contains(f.Text, "100") || !strings.Contains(f.Text, "1000") {
		t.Errorf("в тексте нет обоих чисел — читателю нечего сравнить: %q", f.Text)
	}
}

func TestTunnelCostIsNamedWhenChannelIsExpensive(t *testing.T) {
	evening := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, SampleSize: 100, SampleMin: 100,
		RTTBaselineMs: 67, RTTTunnelMs: 144}
	f := has(Analyze(evening), "latency_tunnel_cost")
	if f == nil {
		t.Fatal("канал дороже прямого плеча на 77 мс — об этом обязано быть сказано")
	}
	if f.Level != LevelWarn || f.Action == "" {
		t.Errorf("вывод без совета бесполезен: %+v", f)
	}
	if has(Analyze(evening), "latency_geography") != nil {
		t.Error("нельзя одновременно объяснять задержку географией и ценой канала")
	}

	morning := evening
	morning.RTTTunnelMs = 66
	if has(Analyze(morning), "latency_tunnel_cost") != nil {
		t.Error("канал не добавил задержки — обвинять его не за что")
	}
	if has(Analyze(morning), "latency_geography") == nil {
		t.Error("равные числа обязаны объясняться географией")
	}
}

func TestLoadLossBlamesThePathNotUs(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: true, SampleSize: 100, SampleMin: 100,
		DataLossPct: 9.8, TunnelDownKbit: 32000, ShapedTunDownKbit: 40500,
		QueueDropped: 392, Cores: 2, Load1: 0.1}
	got := Analyze(f)
	if has(got, "load_our_ceiling") != nil {
		t.Error("нельзя винить наш потолок, когда закачка до него не дошла")
	}
	fin := has(got, "load_path_bottleneck")
	if fin == nil {
		t.Fatal("виновник потерь под нагрузкой не назван — администратор пойдёт крутить тариф")
	}
	if !strings.Contains(fin.Action, "бесполезно") {
		t.Errorf("совет обязан удержать от снижения тарифа: %q", fin.Action)
	}
}

func TestLoadLossNamesOurCeilingWhenWeAreTheLimit(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: true, SampleSize: 100, SampleMin: 100,
		DataLossPct: 2.0, TunnelDownKbit: 44000, ShapedTunDownKbit: 45000,
		QueueDropped: 8000, Cores: 2, Load1: 0.1}
	if has(Analyze(f), "load_our_ceiling") == nil {
		t.Fatal("когда упёрлись в свой потолок, честно сказать об этом обязаны первыми")
	}
}

func TestServerFitForWebButNotForCalls(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: true, SampleSize: 100, SampleMin: 100,
		DataLossPct: 9.8, IdleDataLossPct: 0.27,
		TunnelDownKbit: 32000, ShapedTunDownKbit: 40500, QueueDropped: 392}
	fin := has(Analyze(f), "server_web_not_calls")
	if fin == nil {
		t.Fatal("разрыв между спокойным каналом и закачкой не объяснён")
	}
	if !strings.Contains(fin.Text, "0.27") || !strings.Contains(fin.Text, "9.8") {
		t.Errorf("оба числа обязаны стоять рядом: %q", fin.Text)
	}
}

func TestNoLoadVerdictOnCalmCheck(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: false, SampleSize: 100, SampleMin: 100,
		DataLossPct: 9.8}
	for _, code := range []string{"load_path_bottleneck", "load_our_ceiling", "server_web_not_calls"} {
		if has(Analyze(f), code) != nil {
			t.Errorf("правило %s не имеет права срабатывать без нагрузки", code)
		}
	}
}

func TestConnectionProbeIsNotCalledVoice(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, SampleSize: 100, SampleMin: 100,
		ServiceLossPct: 4.0, DataLossPct: 0.0}
	fin := has(Analyze(f), "icmp_deprioritized")
	if fin == nil {
		t.Fatal("расхождение служебной плоскости и данных обязано объясняться")
	}
	for _, forbidden := range []string{"голосовой поток", "голосовому потоку"} {
		if strings.Contains(fin.Text, forbidden) || strings.Contains(fin.Action, forbidden) {
			t.Errorf("проба соединениями выдана за голос — панель обещает то, чего не мерила: %q", fin.Text+fin.Action)
		}
	}
}

func TestLoadVerdictWarnsAboutProbeCadence(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: true, SampleSize: 100, SampleMin: 100,
		DataLossPct: 4.8, TunnelDownKbit: 32000, ShapedTunDownKbit: 40500, QueueDropped: 392}
	fin := has(Analyze(f), "load_path_bottleneck")
	if fin == nil {
		t.Fatal("виновник не назван")
	}
	if !strings.Contains(fin.Action, "в десять раз чаще") {
		t.Errorf("оговорка о ритме пробы обязана быть: %q", fin.Action)
	}
}

func TestCalmChannelLossIsDiagnosed(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: false, SampleSize: 100, SampleMin: 100,
		ServiceLossPct: 7.0, DataLossPct: 5.0}
	fin := has(Analyze(f), "calm_loss")
	if fin == nil {
		t.Fatal("потери без нагрузки остались без объяснения — администратор увидит противоречие")
	}
	if fin.Level != LevelWarn || !strings.Contains(fin.Title, "7.0") {
		t.Errorf("диагноз обязан называть худшее число и быть предупреждением: %+v", fin)
	}
}

func TestCalmLossSilentOnCleanChannel(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, SampleSize: 100, SampleMin: 100,
		ServiceLossPct: 0.3, DataLossPct: 0.0}
	if has(Analyze(f), "calm_loss") != nil {
		t.Error("на чистом канале тревожить администратора не за что")
	}
}

func TestCalmLossSilentUnderLoad(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: true, DataPlane: vpndriver.Yes,
		HandshakeEver: true, UnderLoad: true, SampleSize: 100, SampleMin: 100,
		DataLossPct: 9.8, TunnelDownKbit: 32000, ShapedTunDownKbit: 40500}
	if has(Analyze(f), "calm_loss") != nil {
		t.Error("под нагрузкой отвечает другое правило — двух диагнозов об одном быть не должно")
	}
}

func TestHandshakeNeverNamesTheKeyAndUsesDirectProbe(t *testing.T) {
	base := Facts{ModeBlack: true, Present: true, Online: false, HandshakeEver: false}
	plain := mustHave(t, Analyze(base), "handshake_never", "молчание сервера обязано объясняться")
	if !strings.Contains(plain.Text, "ключ") {
		t.Errorf("ключ среди причин не назван: %q", plain.Text)
	}
	alive := base
	alive.DirectProbed, alive.DirectAnswers = true, true
	fin := mustHave(t, Analyze(alive), "handshake_never", "сервер жив, рукопожатия нет")
	if !strings.Contains(fin.Text, "отвечает на проверку мимо канала") || !strings.Contains(fin.Text, "ключ") {
		t.Errorf("живой сервер без рукопожатия обязан вести к ключу: %q", fin.Text)
	}
	silent := base
	silent.DirectProbed = true
	fin = mustHave(t, Analyze(silent), "handshake_never", "сервер молчит совсем")
	if !strings.Contains(fin.Text, "не отвечает и на проверку мимо канала") || !strings.Contains(fin.Text, "адрес") {
		t.Errorf("молчащий сервер обязан вести к адресу и пути: %q", fin.Text)
	}
	for _, f := range []Facts{base, alive, silent} {
		if fin := mustHave(t, Analyze(f), "handshake_never", "часы"); !strings.Contains(fin.Text, "из будущего") {
			t.Errorf("случай «часы спешили» потерян: %q", fin.Text)
		}
	}
}

func TestTCPTransportIsFlaggedPermanently(t *testing.T) {
	f := healthy()
	f.Transport = "tcp"
	fin := mustHave(t, Analyze(f), "transport_tcp", "TCP обязан быть помечен")
	if fin.Level != LevelWarn || !strings.Contains(fin.Action, "UDP") {
		t.Fatalf("пометка TCP: %+v", fin)
	}
	f.Transport = "udp"
	if has(Analyze(f), "transport_tcp") != nil {
		t.Fatal("по UDP пометки быть не должно")
	}
	f.Transport, f.ModeBlack = "tcp", false
	if has(Analyze(f), "transport_tcp") != nil {
		t.Fatal("в прямом режиме канал не используется — пометка неуместна")
	}
}

func TestUserspaceCryptoIsNamedHonestly(t *testing.T) {
	f := healthy()
	f.Protocol, f.KernelDataPlane = "openvpn", false
	fin := mustHave(t, Analyze(f), "userspace_crypto", "шифрование в процессе обязано быть названо")
	if fin.Level != LevelInfo {
		t.Fatalf("это оговорка, а не тревога: %+v", fin)
	}
	f.KernelDataPlane = true
	if has(Analyze(f), "userspace_crypto") != nil {
		t.Fatal("при шифровании в ядре оговорки быть не должно")
	}
	f.Protocol, f.KernelDataPlane = "любой", false
	mustHave(t, Analyze(f), "userspace_crypto", "оговорку решает факт, а не имя протокола")
}

func TestHandshakeNeverMentionsFutureClock(t *testing.T) {
	f := Facts{ModeBlack: true, Present: true, Online: false, HandshakeEver: false}
	fin := has(Analyze(f), "handshake_never")
	if fin == nil {
		t.Fatal("молчание сервера обязано объясняться")
	}
	if !strings.Contains(fin.Text, "из будущего") {
		t.Errorf("случай «часы спешили» не назван: %q", fin.Text)
	}
}

func TestProcessFailuresAreNamedNotGeneric(t *testing.T) {
	base := Facts{ModeBlack: true, Protocol: "openvpn", Transport: "udp"}
	cases := map[string]string{
		"server_silent":      "server_silent",
		"tls_verify_failed":  "file_rejected_tls",
		"cert_rejected":      "cert_rejected",
		"rejected_after_tls": "rejected_after_tls",
	}
	for reason, code := range cases {
		f := base
		f.FailReason, f.FailCount = reason, 3
		out := Analyze(f)
		fin := mustHave(t, out, code, reason)
		if fin.Level != LevelError || fin.Action == "" {
			t.Errorf("%s: уровень %v, действие %q", reason, fin.Level, fin.Action)
		}
		if has(out, "no_tunnel") != nil || has(out, "handshake_never") != nil {
			t.Errorf("%s: общий ответ не должен дублировать названный", reason)
		}
		for _, forbidden := range []string{"data-ciphers", "tls-crypt", "verify-x509", "server.conf", "push "} {
			if strings.Contains(fin.Text+fin.Action, forbidden) {
				t.Errorf("%s: текст содержит серверный рецепт %q", reason, forbidden)
			}
		}
		if !strings.Contains(fin.Text, "попыток подряд: 3") {
			t.Errorf("%s: число попыток не названо: %q", reason, fin.Text)
		}
	}

	f := base
	f.FailReason = "tls_verify_failed"
	if fin := mustHave(t, Analyze(f), "file_rejected_tls", "часы"); !strings.Contains(fin.Action, "Проверить время") {
		t.Fatalf("часы обязаны быть первым действием: %q", fin.Action)
	}

	f.RetryPaused = true
	fin := mustHave(t, Analyze(f), "file_rejected_tls", "остановка попыток")
	if !strings.Contains(fin.Text, "прекратила автоматические попытки") ||
		!strings.Contains(fin.Text, "«Применить»") {
		t.Fatalf("остановка не объяснена: %q", fin.Text)
	}
	for _, forbidden := range []string{"блокир", "бан", "чёрн", "лимит", "fail2ban"} {
		if strings.Contains(strings.ToLower(fin.Text), forbidden) {
			t.Fatalf("текст пугает администратора словом %q: %q", forbidden, fin.Text)
		}
	}

	f = base
	f.FailReason, f.DirectProbed, f.DirectAnswers = "server_silent", true, true
	if fin := mustHave(t, Analyze(f), "server_silent", "проба"); !strings.Contains(fin.Text, "сервер жив") {
		t.Fatalf("проба не учтена: %q", fin.Text)
	}

	h := healthy()
	h.Protocol, h.FailReason = "openvpn", "tls_verify_failed"
	if has(Analyze(h), "file_rejected_tls") != nil {
		t.Fatal("подключённый канал не должен показывать прошлый отказ")
	}
}

func TestDataSuspectIsWarningNotVerdict(t *testing.T) {
	f := healthy()
	f.DataSuspect = true
	got := has(Analyze(f), "data_suspect")
	if got == nil || got.Level != LevelWarn || !strings.Contains(got.Text, "не может") {
		t.Fatalf("подозрение без пробы: %+v", got)
	}
	if has(Analyze(healthy()), "data_suspect") != nil {
		t.Fatal("подозрение без признака")
	}
}
