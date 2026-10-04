package logsink

import (
	"testing"

	contractslog "github.com/goravel/framework/contracts/log"
)

func TestFormatLine(t *testing.T) {
	got := FormatLine(contractslog.LevelWarning, "agent error 1006", map[string]any{"b": 2, "a": "x"})
	if want := "<4>agent error 1006 a=x b=2\n"; got != want {
		t.Fatalf("%q, ожидалось %q", got, want)
	}
}

func TestFormatLineNoInjectedLines(t *testing.T) {
	got := FormatLine(contractslog.LevelInfo, "первая\n<3>поддельная", map[string]any{"k": "v\nw"})
	if n := countNewlines(got); n != 1 {
		t.Fatalf("в записи %d переводов строки: %q", n, got)
	}
}

func countNewlines(s string) int {
	n := 0
	for _, r := range s {
		if r == '\n' {
			n++
		}
	}
	return n
}

func TestPriorityAndLevels(t *testing.T) {
	cases := []struct {
		level contractslog.Level
		want  int
	}{
		{contractslog.LevelDebug, 7},
		{contractslog.LevelInfo, 6},
		{contractslog.LevelWarning, 4},
		{contractslog.LevelError, 3},
		{contractslog.LevelFatal, 2},
		{contractslog.LevelPanic, 2},
	}
	for _, c := range cases {
		if got := priority(c.level); got != c.want {
			t.Errorf("уровень %v → %d, ожидалось %d", c.level, got, c.want)
		}
	}
	if ParseLevel("warning") != contractslog.LevelWarning || ParseLevel("мусор") != contractslog.LevelInfo {
		t.Fatal("разбор уровня")
	}
	h, _ := Driver{Level: "info"}.Handle("logging.channels.journal")
	if h.Enabled(contractslog.LevelDebug) || !h.Enabled(contractslog.LevelError) {
		t.Fatal("нижний уровень не соблюдается")
	}
}
