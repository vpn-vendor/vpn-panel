package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"
)

const (
	Dir = "public"
	URL = "/static"
)

const fingerprintLen = 16

var (
	once        sync.Once
	fingerprint string
)

func Fingerprint() string {
	once.Do(func() { fingerprint = Of(os.DirFS(Dir)) })
	return fingerprint
}

func Prefix() string {
	if fp := Fingerprint(); fp != "" {
		return URL + "/" + fp
	}
	return "/" + Dir
}

func Of(fsys fs.FS) string {
	var names []string
	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			continue
		}
		_, _ = io.WriteString(h, name+"\x00")
		_, _ = io.Copy(h, f)
		_ = f.Close()
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))[:fingerprintLen]
}
