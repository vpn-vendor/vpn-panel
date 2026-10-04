package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var packed []byte

//go:embed UPDATED
var updated string

var (
	once  sync.Once
	table map[string]string
)

func load() {
	table = map[string]string{}
	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '\t'); i == 6 {
			table[line[:6]] = line[7:]
		}
	}
}

func Updated() string { return strings.TrimSpace(updated) }

func Vendor(mac string) string {
	hex := normalize(mac)
	if len(hex) < 6 {
		return ""
	}
	if Randomized(mac) {
		return ""
	}
	once.Do(load)
	return table[hex[:6]]
}

func Randomized(mac string) bool {
	hex := normalize(mac)
	if len(hex) < 2 {
		return false
	}
	var b byte
	for _, c := range hex[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'A' && c <= 'F':
			b |= byte(c-'A') + 10
		default:
			return false
		}
	}
	return b&0x02 != 0
}

func normalize(mac string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(mac) {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') {
			b.WriteRune(c)
		}
	}
	return b.String()
}
