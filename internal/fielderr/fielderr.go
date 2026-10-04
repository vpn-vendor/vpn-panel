package fielderr

import (
	"errors"
	"fmt"
	"strings"
)

type Error struct {
	Path string
	Text string
}

func (e Error) Error() string {
	if e.Path == "" {
		return e.Text
	}
	return e.Path + ": " + e.Text
}

type List []Error

func (l *List) Add(path, format string, a ...any) {
	*l = append(*l, Error{Path: path, Text: fmt.Sprintf(format, a...)})
}

func (l *List) Under(prefix string, inner List) {
	for _, e := range inner {
		*l = append(*l, Error{Path: Join(prefix, e.Path), Text: e.Text})
	}
}

func (l List) Err() error {
	if len(l) == 0 {
		return nil
	}
	errs := make([]error, len(l))
	for i, e := range l {
		errs[i] = e
	}
	return errors.Join(errs...)
}

func (l List) First() string {
	if len(l) == 0 {
		return ""
	}
	return l[0].Text
}

func Join(parent, name string) string {
	switch {
	case parent == "":
		return name
	case name == "" || strings.HasPrefix(name, "["):
		return parent + name
	}
	return parent + "." + name
}

func Index(path string, i int) string { return fmt.Sprintf("%s[%d]", path, i) }

func (l List) Has(path string) bool {
	for _, e := range l {
		if e.Path == path {
			return true
		}
	}
	return false
}

func (l List) Beyond(base List) List {
	old := map[Error]bool{}
	for _, e := range base {
		old[e] = true
	}
	var out List
	for _, e := range l {
		if !old[e] {
			out = append(out, e)
		}
	}
	return out
}

func Row(path string, i int, key string) string {
	if key == "" || strings.ContainsAny(key, "[]") {
		return Index(path, i)
	}
	return path + "[" + key + "]"
}
