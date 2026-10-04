package durable

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type memFS struct {
	dirs map[string]*memDir
	seq  int

	onStep func()
}

type memDir struct {
	cur, dur map[string]*memNode
}

type memNode struct {
	data, durable []byte
	dir           bool
}

func newMemFS(dirs ...string) *memFS {
	m := &memFS{dirs: map[string]*memDir{}}
	for _, d := range dirs {
		m.dirs[d] = &memDir{cur: map[string]*memNode{}, dur: map[string]*memNode{}}
	}
	return m
}

func (m *memFS) step() {
	if m.onStep != nil {
		m.onStep()
	}
}

func (m *memFS) dir(name string) (*memDir, error) {
	d, ok := m.dirs[filepath.Clean(name)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return d, nil
}

func (m *memFS) put(path string, data []byte) {
	d := m.dirs[filepath.Dir(path)]
	n := &memNode{data: data, durable: data}
	d.cur[filepath.Base(path)], d.dur[filepath.Base(path)] = n, n
}

func (m *memFS) afterCrash() map[string]string {
	out := map[string]string{}
	for path, d := range m.dirs {
		if !m.dirSurvives(path) {
			continue
		}
		for name, n := range d.dur {
			if !n.dir {
				out[filepath.Join(path, name)] = string(n.durable)
			}
		}
	}
	return out
}

func (m *memFS) dirSurvives(path string) bool {
	parent, ok := m.dirs[filepath.Dir(path)]
	if !ok || filepath.Dir(path) == path {
		return true
	}
	n, ok := parent.dur[filepath.Base(path)]
	return ok && n.dir && m.dirSurvives(filepath.Dir(path))
}

func (m *memFS) CreateTemp(dir, pattern string) (file, error) {
	d, err := m.dir(dir)
	if err != nil {
		return nil, err
	}
	m.seq++
	name := strings.Replace(pattern, "*", fmt.Sprint(m.seq), 1)
	n := &memNode{}
	d.cur[name] = n
	m.step()
	return &memFile{fs: m, node: n, name: filepath.Join(dir, name)}, nil
}

func (m *memFS) Rename(from, to string) error {
	fd, err := m.dir(filepath.Dir(from))
	if err != nil {
		return err
	}
	td, err := m.dir(filepath.Dir(to))
	if err != nil {
		return err
	}
	n, ok := fd.cur[filepath.Base(from)]
	if !ok {
		return &fs.PathError{Op: "rename", Path: from, Err: fs.ErrNotExist}
	}
	delete(fd.cur, filepath.Base(from))
	td.cur[filepath.Base(to)] = n
	m.step()
	return nil
}

func (m *memFS) Remove(name string) error {
	d, err := m.dir(filepath.Dir(name))
	if err != nil {
		return err
	}
	if _, ok := d.cur[filepath.Base(name)]; !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	delete(d.cur, filepath.Base(name))
	m.step()
	return nil
}

func (m *memFS) SyncDir(dir string) error {
	d, err := m.dir(dir)
	if err != nil {
		return err
	}
	d.dur = map[string]*memNode{}
	for k, v := range d.cur {
		d.dur[k] = v
	}
	m.step()
	return nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	d, err := m.dir(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	n, ok := d.cur[filepath.Base(name)]
	if !ok || n.dir {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	return n.data, nil
}

func (m *memFS) ReadDir(dir string) ([]string, error) {
	d, err := m.dir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for k, n := range d.cur {
		if !n.dir {
			names = append(names, k)
		}
	}
	return names, nil
}

func (m *memFS) Mkdir(dir string, _ os.FileMode) error {
	dir = filepath.Clean(dir)
	if _, ok := m.dirs[dir]; ok {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: fs.ErrExist}
	}
	parent, err := m.dir(filepath.Dir(dir))
	if err != nil {
		return err
	}
	parent.cur[filepath.Base(dir)] = &memNode{dir: true}
	m.dirs[dir] = &memDir{cur: map[string]*memNode{}, dur: map[string]*memNode{}}
	m.step()
	return nil
}

func (m *memFS) Exists(name string) bool {
	name = filepath.Clean(name)
	if _, ok := m.dirs[name]; ok {
		return true
	}
	d, ok := m.dirs[filepath.Dir(name)]
	if !ok {
		return false
	}
	_, ok = d.cur[filepath.Base(name)]
	return ok
}

type memFile struct {
	fs   *memFS
	node *memNode
	name string
}

func (f *memFile) Name() string { return f.name }

func (f *memFile) Write(p []byte) (int, error) {
	f.node.data = append(append([]byte{}, f.node.data...), p...)
	f.fs.step()
	return len(p), nil
}

func (f *memFile) Chmod(os.FileMode) error { return nil }
func (f *memFile) Chown(int, int) error    { return nil }
func (f *memFile) Close() error            { return nil }

func (f *memFile) Sync() error {
	f.node.durable = f.node.data
	f.fs.step()
	return nil
}
