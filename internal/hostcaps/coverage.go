package hostcaps

import (
	"reflect"
	"sort"
)

func ZeroFields(v any, skip ...string) []string {
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}
	var out []string
	walk(reflect.ValueOf(v), "", skipped, &out)
	sort.Strings(out)
	return out
}

func walk(v reflect.Value, path string, skip map[string]bool, out *[]string) {
	if path != "" && skip[path] {
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			*out = append(*out, path)
			return
		}
		walk(v.Elem(), path, skip, out)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			name := t.Field(i).Name
			if path != "" {
				name = path + "." + name
			}
			walk(v.Field(i), name, skip, out)
		}
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			*out = append(*out, path)
			return
		}
		if v.Kind() == reflect.Slice {
			walk(v.Index(0), path+"[0]", skip, out)
		}
	default:
		if v.IsZero() {
			*out = append(*out, path)
		}
	}
}
