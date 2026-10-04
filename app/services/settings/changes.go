package settings

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

func Changes(cur, want any) (set map[string]string, del []string, err error) {
	cv, wv := reflect.ValueOf(cur), reflect.ValueOf(want)
	if cv.Type() != wv.Type() || cv.Kind() != reflect.Struct {
		return nil, nil, fmt.Errorf("разница настроек: нужны два значения одного раздела")
	}
	set = map[string]string{}
	t := cv.Type()
	for i := range t.NumField() {
		key := t.Field(i).Tag.Get("setting")
		if key == "" {
			continue
		}
		c, w := cv.Field(i), wv.Field(i)
		if w.Kind() == reflect.Map {
			for _, k := range w.MapKeys() {
				nv, err := encode(w.MapIndex(k))
				if err != nil {
					return nil, nil, fmt.Errorf("%s%s: %w", key, k.String(), err)
				}
				if old := c.MapIndex(k); !old.IsValid() || !reflect.DeepEqual(old.Interface(), w.MapIndex(k).Interface()) {
					set[key+k.String()] = nv
				}
			}
			for _, k := range c.MapKeys() {
				if !w.MapIndex(k).IsValid() {
					del = append(del, key+k.String())
				}
			}
			continue
		}
		if reflect.DeepEqual(c.Interface(), w.Interface()) {
			continue
		}
		nv, err := encode(w)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", key, err)
		}
		set[key] = nv
	}
	sort.Strings(del)
	return set, del, nil
}

func encode(v reflect.Value) (string, error) {
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			return "1", nil
		}
		return "0", nil
	case reflect.Int, reflect.Int64, reflect.Int32:
		return strconv.FormatInt(v.Int(), 10), nil
	case reflect.String:
		return v.String(), nil
	}
	return "", fmt.Errorf("тип %s не пишется в настройки", v.Type())
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
