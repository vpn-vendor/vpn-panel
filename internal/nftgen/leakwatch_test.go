package nftgen

import (
	"strings"
	"testing"
)

func rulesWith(chain, suffix string) []string {
	var out []string
	for _, ln := range strings.Split(chain, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasSuffix(ln, " "+suffix) && !strings.HasPrefix(ln, "oifname") {
			out = append(out, strings.TrimSuffix(ln, " "+suffix))
		}
	}
	return out
}

func TestLeakWatchMirrorsOutput(t *testing.T) {
	black := blackPlan()
	out := string(black.Generate())
	allowed := rulesWith(chainBody(t, out, "output"), "accept")
	exempt := rulesWith(chainBody(t, out, "leak_watch"), "return")
	if len(allowed) < 4 || strings.Join(allowed, "\n") != strings.Join(exempt, "\n") {
		t.Fatalf("разрешения выхода и исключения сигнализации разошлись:\n%v\n---\n%v", allowed, exempt)
	}
	watch := chainBody(t, out, "leak_watch")
	for _, want := range []string{
		"type filter hook postrouting priority srcnat + 10; policy accept;",
		`oifname != { "ens3" } return`,
		`counter comment "` + LeakWatchComment + `"`,
	} {
		if !strings.Contains(watch, want) {
			t.Errorf("в сигнализации нет %q:\n%s", want, watch)
		}
	}
	lines := strings.Split(strings.TrimSpace(watch), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); !strings.HasPrefix(last, "counter") {
		t.Errorf("счётчик обязан стоять последним: %q", last)
	}
}

func TestMarkKeptOnReplies(t *testing.T) {
	black := blackPlan()
	out := string(black.Generate())
	if !strings.Contains(chainBody(t, out, "mark_save"), "meta mark 0xca6c ct mark set meta mark") {
		t.Error("метка исходящего не сохраняется в соединении")
	}
	if !strings.Contains(chainBody(t, out, "mark_restore"), "ct mark 0xca6c meta mark set ct mark") {
		t.Error("метка не возвращается ответу")
	}
	white := blackPlan()
	white.Tunnel = nil
	wout := string(white.Generate())
	for _, name := range []string{"leak_watch", "mark_save", "mark_restore"} {
		if strings.Contains(wout, "chain "+name+" {") {
			t.Errorf("в прямом режиме цепочки %s быть не должно", name)
		}
	}
}
