package change

import (
	"encoding/json"
	"reflect"

	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type Rejected struct{ Errors fielderr.List }

func (r *Rejected) Error() string { return r.Errors.First() }

type Section[T any] struct {
	Read     func() (T, error)
	Validate func(T) fielderr.List
	Apply    func(cur, want T) error
}

var Durable func() error

func Apply[T any](s Section[T], edit func(*T) error) (T, error) {
	cur, want, err := prepare(s, edit)
	if err != nil {
		return cur, err
	}
	if err := s.Apply(cur, want); err != nil {
		return want, err
	}
	if Durable != nil {
		return want, Durable()
	}
	return want, nil
}

func Check[T any](s Section[T], edit func(*T) error) error {
	_, _, err := prepare(s, edit)
	return err
}

func prepare[T any](s Section[T], edit func(*T) error) (cur, want T, err error) {
	if cur, err = s.Read(); err != nil {
		return cur, want, err
	}
	if want, err = clone(cur); err != nil {
		return cur, want, err
	}
	if err = edit(&want); err != nil {
		return cur, want, err
	}
	if errs := s.Validate(want).Beyond(s.Validate(cur)); len(errs) > 0 {
		return cur, want, &Rejected{Errors: errs}
	}
	return cur, want, nil
}

func clone[T any](v T) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func Rows[T any](cur, want []T, key func(T) string) (added, changed, removed []T) {
	old := map[string]T{}
	for _, r := range cur {
		old[key(r)] = r
	}
	seen := map[string]bool{}
	for _, w := range want {
		k := key(w)
		seen[k] = true
		c, ok := old[k]
		switch {
		case !ok:
			added = append(added, w)
		case !reflect.DeepEqual(c, w):
			changed = append(changed, w)
		}
	}
	for _, c := range cur {
		if !seen[key(c)] {
			removed = append(removed, c)
		}
	}
	return added, changed, removed
}
