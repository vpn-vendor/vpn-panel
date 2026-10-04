package backup

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/fielderr"
)

type Def[T any] struct {
	Name    settings.Section
	Version int

	Up map[int]func(json.RawMessage) (json.RawMessage, error)

	After []settings.Section

	Read func() (T, error)

	Validate func(v T, d Desired) fielderr.List

	Apply func(cur, want T, ip string) error
}

type Desired map[settings.Section]any

func DesiredOf[T any](d Desired, name settings.Section) (T, bool) {
	v, ok := d[name].(T)
	return v, ok
}

type Entry interface {
	Name() settings.Section
	Spec() backupfile.Spec
	After() []settings.Section

	Shape() reflect.Type
	Export() (json.RawMessage, error)

	Decode(json.RawMessage) (any, error)

	Validate(v any, d Desired) fielderr.List
	HasValidate() bool

	Apply(cur, want any, ip string) error
	HasApply() bool
}

func Of[T any](d Def[T]) Entry { return entry[T]{d} }

type entry[T any] struct{ d Def[T] }

func (e entry[T]) Name() settings.Section    { return e.d.Name }
func (e entry[T]) After() []settings.Section { return e.d.After }
func (e entry[T]) Shape() reflect.Type       { return reflect.TypeFor[T]() }

func (e entry[T]) Spec() backupfile.Spec {
	return backupfile.Spec{Version: e.d.Version, Up: e.d.Up}
}

func (e entry[T]) Export() (json.RawMessage, error) {
	v, err := e.d.Read()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (e entry[T]) HasValidate() bool { return e.d.Validate != nil }

func (e entry[T]) HasApply() bool { return e.d.Apply != nil }

func (e entry[T]) Apply(cur, want any, ip string) error {
	c, ok1 := cur.(T)
	w, ok2 := want.(T)
	switch {
	case !ok1 || !ok2:
		return errors.New("данные не того раздела")
	case e.d.Apply == nil:
		return errors.New("у раздела нет применения")
	}
	return e.d.Apply(c, w, ip)
}

func (e entry[T]) Validate(v any, d Desired) fielderr.List {
	t, ok := v.(T)
	if !ok {
		var errs fielderr.List
		errs.Add("", "данные не того раздела")
		return errs
	}
	if e.d.Validate == nil {
		var errs fielderr.List
		errs.Add("", "у раздела нет проверки")
		return errs
	}
	return e.d.Validate(t, d)
}

func (e entry[T]) Decode(raw json.RawMessage) (any, error) {
	var v T
	if err := strictUnmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func Specs(entries []Entry) backupfile.Specs {
	out := backupfile.Specs{}
	for _, e := range entries {
		out[string(e.Name())] = e.Spec()
	}
	return out
}
