package admission

import "strings"

type Rule struct {
	Method string
	Prefix string
	Class  Class
}

func Classify(rules []Rule, method, path string) (Class, bool) {
	best, bestLen, found := Ordinary, -1, false
	for _, r := range rules {
		if r.Method != "" && r.Method != method {
			continue
		}
		if !matchPrefix(path, r.Prefix) {
			continue
		}
		l := len(r.Prefix)
		if l > bestLen || (l == bestLen && r.Method != "") {
			best, bestLen, found = r.Class, l, true
		}
	}
	return best, found
}

func matchPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	p := strings.TrimSuffix(prefix, "/")
	return path == p || strings.HasPrefix(path, p+"/")
}
