package durable

import (
	"os"
	"path/filepath"
	"testing"
)

const target = "/etc/app/plan.conf"

func crashes(t *testing.T, m *memFS, act func() error) (during []map[string]string, after map[string]string) {
	t.Helper()
	prev := sys
	sys = m
	defer func() { sys = prev }()
	m.onStep = func() { during = append(during, m.afterCrash()) }
	if err := act(); err != nil {
		t.Fatalf("действие не удалось: %v", err)
	}
	m.onStep = nil
	return during, m.afterCrash()
}

func torn(points []map[string]string, old *string, fresh string) []string {
	var bad []string
	for _, p := range points {
		got, ok := p[target]
		switch {
		case ok && got == fresh:
		case ok && old != nil && got == *old:
		case !ok && old == nil:
		default:
			if !ok {
				got = "<файла нет>"
			}
			bad = append(bad, got)
		}
	}
	return bad
}

func TestWriteSurvivesPowerCutAtAnyPoint(t *testing.T) {
	old := "прежнее"
	m := newMemFS("/etc/app")
	m.put(target, []byte(old))
	during, after := crashes(t, m, func() error { return Write(target, []byte("новое"), 0o600) })
	if bad := torn(during, &old, "новое"); len(bad) > 0 {
		t.Fatalf("после обрыва файл не прежний и не новый: %q", bad)
	}
	if after[target] != "новое" {
		t.Fatalf("запись вернула успех, а после обрыва в файле %q", after[target])
	}
	if len(after) != 1 {
		t.Fatalf("после записи остались лишние файлы: %v", after)
	}
}

func TestWriteNewFileSurvivesPowerCut(t *testing.T) {
	m := newMemFS("/etc/app")
	during, after := crashes(t, m, func() error { return Write(target, []byte("новое"), 0o600) })
	if bad := torn(during, nil, "новое"); len(bad) > 0 {
		t.Fatalf("после обрыва на месте нового файла мусор: %q", bad)
	}
	if after[target] != "новое" {
		t.Fatalf("после обрыва в файле %q", after[target])
	}
}

func TestModelCatchesWriteWithoutSync(t *testing.T) {
	old := "прежнее"
	m := newMemFS("/etc/app")
	m.put(target, []byte(old))
	during, after := crashes(t, m, func() error {
		f, err := sys.CreateTemp("/etc/app", ".plan.conf.*"+tempSuffix)
		if err != nil {
			return err
		}
		if _, err := f.Write([]byte("новое")); err != nil {
			return err
		}
		return sys.Rename(f.Name(), target)
	})
	if after[target] == "новое" {
		t.Fatal("модель считает надёжной запись без сброса — она ничего не проверяет")
	}
	_ = during
}

func TestModelCatchesRenameSyncedBeforeData(t *testing.T) {
	old := "прежнее"
	m := newMemFS("/etc/app")
	m.put(target, []byte(old))
	during, _ := crashes(t, m, func() error {
		f, err := sys.CreateTemp("/etc/app", ".plan.conf.*"+tempSuffix)
		if err != nil {
			return err
		}
		if _, err := f.Write([]byte("новое")); err != nil {
			return err
		}
		if err := sys.Rename(f.Name(), target); err != nil {
			return err
		}
		if err := sys.SyncDir("/etc/app"); err != nil {
			return err
		}
		return f.Sync()
	})
	if len(torn(during, &old, "новое")) == 0 {
		t.Fatal("модель не видит пустой файл при переносе раньше содержимого")
	}
}

func TestRemoveDoesNotResurrect(t *testing.T) {
	m := newMemFS("/etc/app")
	m.put(target, []byte("отметка"))
	_, after := crashes(t, m, func() error { return Remove(target) })
	if _, ok := after[target]; ok {
		t.Fatal("удалённый файл вернулся после обрыва питания")
	}

	m = newMemFS("/etc/app")
	m.put(target, []byte("отметка"))
	_, after = crashes(t, m, func() error { return sys.Remove(target) })
	if _, ok := after[target]; !ok {
		t.Fatal("модель не видит воскресшего файла при удалении без сброса")
	}
}

func TestRemoveAbsentIsNotAnError(t *testing.T) {
	m := newMemFS("/etc/app")
	crashes(t, m, func() error { return Remove(target) })
}

func TestMkdirAllThenWriteSurvives(t *testing.T) {
	m := newMemFS("/etc")
	path := "/etc/app/sub/plan.conf"
	_, after := crashes(t, m, func() error {
		if err := MkdirAll("/etc/app/sub", 0o755); err != nil {
			return err
		}
		return Write(path, []byte("новое"), 0o600)
	})
	if after[path] != "новое" {
		t.Fatalf("файл в новом каталоге не пережил обрыв: %v", after)
	}
}

func TestStageAbortLeavesNothing(t *testing.T) {
	old := "прежнее"
	m := newMemFS("/etc/app")
	m.put(target, []byte(old))
	_, after := crashes(t, m, func() error {
		s, err := Stage(target, []byte("непроверенное"), 0o600)
		if err != nil {
			return err
		}
		if !IsTemp(filepath.Base(s.Path())) || filepath.Dir(s.Path()) != "/etc/app" {
			t.Errorf("подготовленный файл не рядом с целью или не узнаётся: %s", s.Path())
		}
		s.Abort()
		return nil
	})
	if len(after) != 1 || after[target] != old {
		t.Fatalf("отмена оставила следы: %v", after)
	}
}

func TestCommitTwiceIsRefused(t *testing.T) {
	m := newMemFS("/etc/app")
	crashes(t, m, func() error {
		s, err := Stage(target, []byte("новое"), 0o600)
		if err != nil {
			return err
		}
		if err := s.Commit(); err != nil {
			return err
		}
		if s.Commit() == nil {
			t.Error("повторное закрепление прошло молча")
		}
		s.Abort()
		return nil
	})
	if got, _ := m.ReadFile(target); string(got) != "новое" {
		t.Fatalf("отмена после закрепления тронула файл: %q", got)
	}
}

func TestWriteIfChanged(t *testing.T) {
	m := newMemFS("/etc/app")
	m.put(target, []byte("то же"))
	steps := 0
	prev := sys
	sys = m
	defer func() { sys = prev }()
	m.onStep = func() { steps++ }
	changed, err := WriteIfChanged(target, []byte("то же"), 0o600)
	if err != nil || changed || steps != 0 {
		t.Fatalf("то же содержимое: changed=%v err=%v, операций записи %d", changed, err, steps)
	}
	changed, err = WriteIfChanged(target, []byte("другое"), 0o600)
	if err != nil || !changed {
		t.Fatalf("другое содержимое: changed=%v err=%v", changed, err)
	}
}

func TestSweepRemovesOnlyOwnLeftovers(t *testing.T) {
	m := newMemFS("/etc/app")
	m.put(target, []byte("действующий"))
	m.put("/etc/app/.plan.conf.7"+tempSuffix, []byte("недописанный секрет"))
	m.put("/etc/app/.hidden", []byte("чужой скрытый"))
	m.put("/etc/app/other"+tempSuffix, []byte("чужой с похожим хвостом"))
	var n int
	_, after := crashes(t, m, func() (err error) { n, err = Sweep("/etc/app"); return err })
	if n != 1 || len(after) != 3 {
		t.Fatalf("убрано %d, осталось после обрыва: %v", n, after)
	}
	if n, err := Sweep("/нет/такого"); n != 0 || err != nil {
		t.Fatalf("каталога нет: n=%d err=%v", n, err)
	}
}

func TestOnRealFilesystem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.conf")
	if err := Write(path, []byte("первое"), 0o640); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteIfChanged(path, []byte("второе"), 0o640); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("права %v, ошибка %v", st.Mode().Perm(), err)
	}
	if got, _ := os.ReadFile(path); string(got) != "второе" { //nolint:gosec
		t.Fatalf("содержимое %q", got)
	}
	s, err := Stage(path, []byte("третье"), 0o640, Owner(os.Getuid(), os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(s.Path()); string(got) != "третье" { //nolint:gosec
		t.Fatalf("подготовленный файл: %q", got)
	}
	s.Abort()
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("в каталоге остатки: %v", entries)
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("повторное удаление: %v", err)
	}
}

func TestSyncFile(t *testing.T) {
	dir := t.TempDir()
	if err := SyncFile(filepath.Join(dir, "нет-такого")); err != nil {
		t.Fatalf("отсутствующий файл — не ошибка: %v", err)
	}
	path := filepath.Join(dir, "журнал")
	if err := os.WriteFile(path, []byte("запись"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncFile(path); err != nil {
		t.Fatal(err)
	}
}
