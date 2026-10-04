package logsink

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	contractslog "github.com/goravel/framework/contracts/log"
)

var (
	outMu  sync.RWMutex
	output io.Writer = os.Stderr
)

func SetOutput(w io.Writer) {
	outMu.Lock()
	output = w
	outMu.Unlock()
}

func write(line string) error {
	outMu.RLock()
	w := output
	outMu.RUnlock()
	_, err := io.WriteString(w, line)
	return err
}

type Driver struct {
	Level string
}

var (
	_ contractslog.Logger  = Driver{}
	_ contractslog.Handler = handler{}
)

func (d Driver) Handle(string) (contractslog.Handler, error) {
	return handler{min: ParseLevel(d.Level)}, nil
}

type handler struct{ min contractslog.Level }

func (h handler) Enabled(level contractslog.Level) bool { return level >= h.min }

func (h handler) Handle(e contractslog.Entry) error {
	return write(FormatLine(e.Level(), e.Message(), e.Data()))
}

func ParseLevel(s string) contractslog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return contractslog.LevelDebug
	case "warning", "warn":
		return contractslog.LevelWarning
	case "error":
		return contractslog.LevelError
	case "fatal":
		return contractslog.LevelFatal
	case "panic":
		return contractslog.LevelPanic
	default:
		return contractslog.LevelInfo
	}
}

func priority(level contractslog.Level) int {
	switch {
	case level >= contractslog.LevelFatal:
		return 2
	case level >= contractslog.LevelError:
		return 3
	case level >= contractslog.LevelWarning:
		return 4
	case level >= contractslog.LevelInfo:
		return 6
	default:
		return 7
	}
}

func FormatLine(level contractslog.Level, msg string, data map[string]any) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "<%d>%s", priority(level), oneLine(msg))
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(&b, " %s=%s", oneLine(k), oneLine(fmt.Sprint(data[k])))
	}
	b.WriteByte('\n')
	return b.String()
}

func oneLine(s string) string {
	return strings.NewReplacer("\r\n", " ⏎ ", "\n", " ⏎ ", "\r", " ⏎ ").Replace(strings.TrimRight(s, "\n"))
}
