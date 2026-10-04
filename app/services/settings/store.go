package settings

import (
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

func Get(key string) string {
	v, _ := Value(key)
	return v
}

func Value(key string) (string, bool) {
	if _, ok := Lookup(key); !ok {
		log.Printf("settings: чтение %q: %v", key, ErrUndeclared)
		return "", false
	}
	var row models.Setting
	if err := facades.Orm().Query().Where("key", key).First(&row); err != nil || row.Key == "" {
		return "", false
	}
	return row.Value, true
}

var ErrNotDurable = errors.New("настройки записаны, но не закреплены на диске — повторите")

func Durable() error {
	path := facades.Config().GetString("database.connections.sqlite.database")
	if path == "" {
		return ErrNotDurable
	}
	for _, f := range []string{path + "-wal", path} {
		if err := durable.SyncFile(f); err != nil {
			return fmt.Errorf("%w: %v", ErrNotDurable, err)
		}
	}
	return nil
}

func Set(key, value string) error { return setIn(facades.Orm().Query(), key, value) }

func setIn(q orm.Query, key, value string) error {
	if _, ok := Lookup(key); !ok {
		return fmt.Errorf("запись %q: %w", key, ErrUndeclared)
	}
	now := time.Now()
	var row models.Setting
	if err := q.Where("key", key).First(&row); err != nil || row.Key == "" {
		return q.Create(&models.Setting{Key: key, Value: value, UpdatedAt: now})
	}
	_, err := q.Model(&models.Setting{}).Where("key", key).
		Update(map[string]any{"value": value, "updated_at": now})
	return err
}

func WriteChanged(cur, want any) error {
	return facades.Orm().Transaction(func(tx orm.Query) error { return WriteChangedIn(tx, cur, want) })
}

func WriteChangedIn(q orm.Query, cur, want any) error {
	set, del, err := Changes(cur, want)
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(set) {
		if err := setIn(q, k, set[k]); err != nil {
			return err
		}
	}
	for _, k := range del {
		if err := DeleteIn(q, k); err != nil {
			return err
		}
	}
	return nil
}

func SetIn(q orm.Query, key, value string) error { return setIn(q, key, value) }

func DeleteIn(q orm.Query, key string) error {
	if _, ok := Lookup(key); !ok {
		return fmt.Errorf("удаление %q: %w", key, ErrUndeclared)
	}
	_, err := q.Where("key", key).Delete(&models.Setting{})
	return err
}

func ForgetOwned(q orm.Query, owner Owner, id string) error {
	if err := DropOwned(q, owner, id); err != nil {
		return err
	}
	_, clear := Owned(Keys, owner, id)
	for _, k := range clear {
		if _, err := q.Where("key", k).Where("value", id).Delete(&models.Setting{}); err != nil {
			return err
		}
	}
	return nil
}

func DropOwned(q orm.Query, owner Owner, id string) error {
	drop, _ := Owned(Keys, owner, id)
	if len(drop) > 0 {
		in := make([]any, len(drop))
		for i, k := range drop {
			in[i] = k
		}
		if _, err := q.WhereIn("key", in).Delete(&models.Setting{}); err != nil {
			return err
		}
	}
	return nil
}

func Prefixed(prefix string) (map[string]string, error) {
	k, ok := Lookup(prefix + "x")
	if !ok || !k.Prefix || k.Name != prefix {
		return nil, fmt.Errorf("чтение %q: %w", prefix, ErrUndeclared)
	}

	var rows []models.Setting
	if err := facades.Orm().Query().Where("key LIKE ?", prefix+"%").Find(&rows); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if tail := strings.TrimPrefix(r.Key, prefix); tail != r.Key && tail != "" {
			out[tail] = r.Value
		}
	}
	return out, nil
}
