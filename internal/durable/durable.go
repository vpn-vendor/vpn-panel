package durable

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const tempSuffix = ".vpn-panel-tmp"

type Option func(*options)

type options struct {
	owned    bool
	uid, gid int
}

func Owner(uid, gid int) Option {
	return func(o *options) { o.owned, o.uid, o.gid = true, uid, gid }
}

type Staged struct {
	tmp, path string
	done      bool
}

func (s *Staged) Path() string { return s.tmp }

func Stage(path string, data []byte, perm os.FileMode, opts ...Option) (*Staged, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := sys.CreateTemp(dir, "."+base+".*"+tempSuffix)
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil && o.owned {
		err = f.Chown(o.uid, o.gid)
	}
	if err == nil {

		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = sys.Remove(tmp)
		return nil, err
	}
	return &Staged{tmp: tmp, path: path}, nil
}

func (s *Staged) Commit() error {
	if s.done {
		return errors.New("durable: подготовленный файл уже закреплён или отменён")
	}
	s.done = true
	if err := sys.Rename(s.tmp, s.path); err != nil {
		_ = sys.Remove(s.tmp)
		return err
	}
	return sys.SyncDir(filepath.Dir(s.path))
}

func (s *Staged) Abort() {
	if s.done {
		return
	}
	s.done = true
	_ = sys.Remove(s.tmp)
}

func Write(path string, data []byte, perm os.FileMode, opts ...Option) error {
	s, err := Stage(path, data, perm, opts...)
	if err != nil {
		return err
	}
	return s.Commit()
}

func WriteIfChanged(path string, data []byte, perm os.FileMode, opts ...Option) (bool, error) {
	if cur, err := sys.ReadFile(path); err == nil && bytes.Equal(cur, data) {
		return false, nil
	}
	return true, Write(path, data, perm, opts...)
}

func Remove(path string) error {
	if err := sys.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return sys.SyncDir(filepath.Dir(path))
}

func MkdirAll(dir string, perm os.FileMode) error {
	dir = filepath.Clean(dir)
	var missing []string
	for d := dir; !sys.Exists(d); d = filepath.Dir(d) {
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := sys.Mkdir(missing[i], perm); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := sys.SyncDir(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	return nil
}

func IsTemp(name string) bool {
	return strings.HasPrefix(name, ".") && strings.HasSuffix(name, tempSuffix)
}

func Sweep(dir string) (int, error) {
	names, err := sys.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, name := range names {
		if !IsTemp(name) {
			continue
		}
		if err := sys.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, sys.SyncDir(dir)
}

func SyncFile(path string) error {
	f, err := os.Open(path) //nolint:gosec
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
