package durable

import (
	"os"
)

type file interface {
	Name() string
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Chown(uid, gid int) error
	Sync() error
	Close() error
}

type filesystem interface {
	CreateTemp(dir, pattern string) (file, error)
	Rename(from, to string) error
	Remove(name string) error
	SyncDir(dir string) error
	ReadFile(name string) ([]byte, error)
	ReadDir(dir string) ([]string, error)
	Mkdir(dir string, perm os.FileMode) error
	Exists(name string) bool
}

var sys filesystem = osFS{}

type osFS struct{}

func (osFS) CreateTemp(dir, pattern string) (file, error) { return os.CreateTemp(dir, pattern) }
func (osFS) Rename(from, to string) error                 { return os.Rename(from, to) }
func (osFS) Remove(name string) error                     { return os.Remove(name) }
func (osFS) ReadFile(name string) ([]byte, error)         { return os.ReadFile(name) } //nolint:gosec
func (osFS) Mkdir(dir string, perm os.FileMode) error     { return os.Mkdir(dir, perm) }

func (osFS) Exists(name string) bool {
	_, err := os.Lstat(name)
	return err == nil
}

func (osFS) ReadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (osFS) SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
