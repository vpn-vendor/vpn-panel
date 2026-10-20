package nftgen

import (
	"bytes"
	"encoding/json"
	"strings"
)

func IsWorking(ruleset []byte) bool {
	if t := bytes.TrimSpace(ruleset); len(t) > 0 && t[0] == '{' {
		return isWorkingJSON(t)
	}
	return isWorkingText(string(ruleset))
}

const (
	ownFamily = "inet"
	ownTable  = "vpn_panel"
)

func isWorkingText(s string) bool {
	depth := 0
	ours, inChain, nat, masq := false, false, false, false
	for _, raw := range strings.Split(s, "\n") {
		code, opens, closes := codeOf(raw)
		f := strings.Fields(code)
		switch {
		case depth == 0 && opens > 0 && len(f) >= 3 && f[0] == "table":
			ours = f[1] == ownFamily && f[2] == ownTable
		case depth == 1 && ours && opens > 0 && len(f) >= 1 && f[0] == "chain":
			inChain, nat, masq = true, false, false
		case depth == 2 && inChain:
			if len(f) >= 4 && f[0] == "type" && f[1] == "nat" && f[2] == "hook" && f[3] == "postrouting" {
				nat = true
			}
			for _, w := range f {
				if w == "masquerade" {
					masq = true
				}
			}
			if nat && masq {
				return true
			}
		}
		depth += opens - closes
		if depth <= 1 {
			inChain = false
		}
	}
	return false
}

func codeOf(line string) (string, int, int) {
	var b strings.Builder
	opens, closes, quoted := 0, 0, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
			b.WriteRune(r)
			continue
		case quoted:
			continue
		case r == '#':
			return b.String(), opens, closes
		case r == '{':
			opens++
		case r == '}':
			closes++
		}
		b.WriteRune(r)
	}
	return b.String(), opens, closes
}

func isWorkingJSON(b []byte) bool {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Family, Table, Name, Type, Hook string
			} `json:"chain"`
			Rule *struct {
				Family, Table, Chain string
				Expr                 []map[string]json.RawMessage
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	nat := map[string]bool{}
	for _, it := range doc.Nftables {
		if c := it.Chain; c != nil && c.Family == ownFamily && c.Table == ownTable && c.Type == "nat" && c.Hook == "postrouting" {
			nat[c.Name] = true
		}
	}
	for _, it := range doc.Nftables {
		r := it.Rule
		if r == nil || r.Family != ownFamily || r.Table != ownTable || !nat[r.Chain] {
			continue
		}
		for _, e := range r.Expr {
			if _, ok := e["masquerade"]; ok {
				return true
			}
		}
	}
	return false
}
