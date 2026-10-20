package nftgen

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	WitnessEarlyChain = "witness_early"
	WitnessLateChain  = "witness_late"
	SeenEarlyCounter  = "seen_early"
	SeenLateCounter   = "seen_late"
)

const (
	witnessEarlyPriority = "raw - 10"
	witnessLatePriority  = "security + 10"

	WitnessEarlyPriority = -310
	WitnessLatePriority  = 60
)

var stdPriorities = map[string]int{
	"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100,
}

func PriorityValue(expr string) (int, bool) {
	s := strings.TrimSpace(expr)
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	name, off, sign := s, "0", 1
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		name, off = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
		if s[i] == '-' {
			sign = -1
		}
	}
	base, ok := stdPriorities[name]
	if !ok || off == "" || strings.Trim(off, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(off)
	if err != nil {
		return 0, false
	}
	return base + sign*n, true
}

func writeWitnesses(b *strings.Builder, allow string) {
	for _, w := range []struct{ chain, priority, counter string }{
		{WitnessEarlyChain, witnessEarlyPriority, SeenEarlyCounter},
		{WitnessLateChain, witnessLatePriority, SeenLateCounter},
	} {
		fmt.Fprintf(b, "\tchain %s {\n", w.chain)
		fmt.Fprintf(b, "\t\ttype filter hook forward priority %s; policy accept;\n", w.priority)
		b.WriteString("\t\tct state != new return\n")
		b.WriteString("\t\tudp dport 3544 return\n")
		b.WriteString("\t\tmeta l4proto 41 return\n")
		b.WriteString("\t\tmeta nfproto != ipv4 return\n")
		fmt.Fprintf(b, "\t\t%s counter name \"%s\"\n", allow, w.counter)
		b.WriteString("\t}\n")
	}
}
